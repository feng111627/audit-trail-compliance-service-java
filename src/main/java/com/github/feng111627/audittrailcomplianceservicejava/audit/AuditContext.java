package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 一次请求的审计上下文。
 *
 * <p>归属关系：
 * <ul>
 *   <li>{@code traceId}：同一次请求（含其中嵌套的多个操作）共享一个 traceId；</li>
 *   <li>{@code spanId}/{@code parentSpanId}：每次进入一个 {@link Audited} 方法压栈一个 span，
 *       离开时弹栈，从而还原操作间的嵌套先后关系；</li>
 *   <li>{@code seq}：同 trace 内严格单调递增的序号，在事件落库（操作完成）时分配，
 *       因此同一 trace 内的记录可按 seq 还原完成先后；嵌套操作内层先完成则序号更小，
 *       父子关系由 spanId/parentSpanId 表达。</li>
 * </ul>
 *
 * <p>线程安全：seq 使用 {@link AtomicLong}；span 栈本身只允许在所属线程操作。
 * 异步线程通过 {@link #snapshotForAsync()} 复制上下文，共享 traceId、操作人与幂等键，
 * 但拥有独立的 span 栈（根 span 的父为原线程当前 span）与独立序号空间，
 * 避免跨线程竞争，也不会串到别的请求。
 */
public class AuditContext {

    private final String traceId;
    private final UserContext user;
    private final String idempotencyKey;
    private final AtomicLong seq = new AtomicLong(0);
    private final Deque<String> spanStack = new ArrayDeque<>();

    public AuditContext(String traceId, String rootSpanId, UserContext user, String idempotencyKey) {
        this.traceId = traceId;
        this.user = user;
        this.idempotencyKey = idempotencyKey;
        if (rootSpanId != null) {
            this.spanStack.push(rootSpanId);
        }
    }

    /** 在当前线程开启一个全新的请求上下文。 */
    public static AuditContext startNew(UserContext user, String idempotencyKey) {
        return new AuditContext(UUID.randomUUID().toString(), newSpanId(), user, idempotencyKey);
    }

    private static String newSpanId() {
        return UUID.randomUUID().toString();
    }

    public String traceId() {
        return traceId;
    }

    public UserContext user() {
        return user;
    }

    public String idempotencyKey() {
        return idempotencyKey;
    }

    /** 申请同 trace 内的下一个序号（线程安全）。 */
    public long nextSeq() {
        return seq.incrementAndGet();
    }

    /** 进入一个被审计操作：压入新 span，返回新 spanId。 */
    public String pushSpan() {
        String spanId = newSpanId();
        spanStack.push(spanId);
        return spanId;
    }

    /** 离开一个被审计操作：弹出当前 span。 */
    public void popSpan() {
        if (!spanStack.isEmpty()) {
            spanStack.pop();
        }
    }

    public String currentSpanId() {
        return spanStack.peekFirst();
    }

    /** 当前操作的父 spanId，即栈中当前 span 之下的那个 span。 */
    public String parentSpanIdOfCurrent() {
        var it = spanStack.iterator();
        if (!it.hasNext()) {
            return null;
        }
        it.next();
        return it.hasNext() ? it.next() : null;
    }

    /**
     * 为异步执行复制上下文：共享 traceId / 操作人 / 幂等键；
     * 新 span 栈的根 span 以复制时刻的当前 span 为父，保持归属关系；
     * 序号计数器独立，异步事件与主线程事件可通过 seq + eventTime 联合排序，
     * 不会互相覆盖序号。
     */
    public AuditContext snapshotForAsync() {
        String parent = currentSpanId();
        String asyncRoot = newSpanId();
        AuditContext copy = new AuditContext(traceId, asyncRoot, user, idempotencyKey);
        // 用一个两元素栈表达 asyncRoot 的父 span 是原线程当前 span：
        // 栈底放 parent、栈顶放 asyncRoot，currentSpanId=asyncRoot、parentSpanIdOfCurrent=parent。
        if (parent != null) {
            copy.spanStack.clear();
            copy.spanStack.push(parent);
            copy.spanStack.push(asyncRoot);
        }
        return copy;
    }
}

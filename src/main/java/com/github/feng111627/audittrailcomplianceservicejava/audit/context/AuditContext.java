package com.github.feng111627.audittrailcomplianceservicejava.audit.context;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * 基于 ThreadLocal 的审计上下文：一次请求一个 scope，
 * 持有 requestId 与该请求内单调递增的序列号。异步线程通过快照恢复，
 * 共享同一个序列号计数器，保证归属正确、先后关系可排、且不串请求。
 */
public final class AuditContext {

    private AuditContext() {
    }

    /** 跨线程传递的不可变快照（序列号计数器为共享引用）。 */
    public record Snapshot(String requestId, AtomicLong sequence, boolean async) {
    }

    /** restore 返回的 AutoCloseable 句柄，关闭时恢复线程原状态。 */
    public static final class Scope implements AutoCloseable {
        private final RequestScope previous;

        Scope(RequestScope previous) {
            this.previous = previous;
        }

        @Override
        public void close() {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        }
    }

    private static final class RequestScope {
        private final String requestId;
        private final AtomicLong sequence;
        private final boolean async;

        RequestScope(String requestId, AtomicLong sequence, boolean async) {
            this.requestId = requestId;
            this.sequence = sequence;
            this.async = async;
        }
    }

    private static final ThreadLocal<RequestScope> CURRENT = new ThreadLocal<>();

    /** 在请求入口开启一个新的审计 scope。 */
    public static void beginRequest(String requestId) {
        CURRENT.set(new RequestScope(requestId, new AtomicLong(0), false));
    }

    /** 请求结束清理，防止线程复用导致串请求。 */
    public static void endRequest() {
        CURRENT.remove();
    }

    public static boolean isActive() {
        return CURRENT.get() != null;
    }

    public static String currentRequestId() {
        RequestScope s = CURRENT.get();
        return s == null ? null : s.requestId;
    }

    public static boolean isAsync() {
        RequestScope s = CURRENT.get();
        return s != null && s.async;
    }

    /** 取下一个请求内序列号，多线程并发也不会重复。 */
    public static long nextSequence() {
        RequestScope s = CURRENT.get();
        if (s == null) {
            throw new IllegalStateException("审计上下文未初始化");
        }
        return s.sequence.incrementAndGet();
    }

    /** 抓取当前线程快照，供异步线程恢复。 */
    public static Snapshot snapshot() {
        RequestScope s = CURRENT.get();
        if (s == null) {
            return null;
        }
        return new Snapshot(s.requestId, s.sequence, s.async);
    }

    /** 在当前线程恢复快照，异步子线程标记为 async=true。 */
    public static Scope restore(Snapshot snapshot) {
        RequestScope previous = CURRENT.get();
        if (snapshot != null) {
            CURRENT.set(new RequestScope(snapshot.requestId(), snapshot.sequence(), true));
        }
        return new Scope(previous);
    }

    /** 包装 Runnable，使其在异步线程里仍携带当前审计上下文。 */
    public static Runnable wrap(Runnable task) {
        Snapshot snapshot = snapshot();
        return () -> {
            try (Scope ignored = restore(snapshot)) {
                task.run();
            }
        };
    }

    /** 包装 Supplier，使其在异步线程里仍携带当前审计上下文。 */
    public static <T> Supplier<T> wrap(Supplier<T> task) {
        Snapshot snapshot = snapshot();
        return () -> {
            try (Scope ignored = restore(snapshot)) {
                return task.get();
            }
        };
    }
}

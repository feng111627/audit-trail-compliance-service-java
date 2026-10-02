package com.github.feng111627.audittrailcomplianceservicejava.audit;

/**
 * 审计上下文的线程级持有者（基于 {@link ThreadLocal}）。
 *
 * <p>请求过滤器负责 set 与 clear；异步线程需主动 set 复制来的上下文并在结束时 clear，
 * 保证线程池复用线程时不会串请求。
 */
public final class AuditContextHolder {

    private static final ThreadLocal<AuditContext> HOLDER = new ThreadLocal<>();

    private AuditContextHolder() {
    }

    public static AuditContext get() {
        return HOLDER.get();
    }

    public static void set(AuditContext context) {
        HOLDER.set(context);
    }

    public static void clear() {
        HOLDER.remove();
    }
}

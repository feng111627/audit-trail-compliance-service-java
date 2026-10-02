package com.github.feng111627.audittrailcomplianceservicejava.audit.security;

/** 当前调用方的线程级上下文，供留痕与鉴权读取。 */
public final class AuditSecurityContext {

    private AuditSecurityContext() {
    }

    private static final ThreadLocal<AuditUser> CURRENT = new ThreadLocal<>();

    public static void set(AuditUser user) {
        CURRENT.set(user);
    }

    public static AuditUser get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }

    /** 快照供异步线程携带。 */
    public static AuditUser snapshot() {
        return CURRENT.get();
    }

    public static void restore(AuditUser user) {
        if (user == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(user);
        }
    }
}

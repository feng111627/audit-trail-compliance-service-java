package com.github.feng111627.audittrailcomplianceservicejava.audit.security;

/** 明确的访问拒绝异常，携带可区分原因，而非静默返回空。 */
public class AuditAccessDeniedException extends RuntimeException {

    private final AccessDeniedReason reason;

    public AuditAccessDeniedException(AccessDeniedReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public AccessDeniedReason getReason() {
        return reason;
    }
}

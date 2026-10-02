package com.github.feng111627.audittrailcomplianceservicejava.audit;

/** 越权访问异常，携带可区分的拒绝原因。 */
public class AccessDeniedException extends RuntimeException {
    private final AccessDeniedReason reason;

    public AccessDeniedException(AccessDeniedReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public AccessDeniedReason reason() {
        return reason;
    }
}

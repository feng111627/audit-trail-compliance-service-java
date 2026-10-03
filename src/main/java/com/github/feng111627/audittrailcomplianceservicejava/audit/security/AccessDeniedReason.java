package com.github.feng111627.audittrailcomplianceservicejava.audit.security;

/** 越权/拒绝原因，对外可区分。 */
public enum AccessDeniedReason {
    UNAUTHENTICATED,
    MISSING_QUERY_CRITERIA,
    NOT_RESOURCE_OWNER,
    READ_FORBIDDEN,
    EXPORT_FORBIDDEN,
    INTEGRITY_VERIFY_FORBIDDEN
}

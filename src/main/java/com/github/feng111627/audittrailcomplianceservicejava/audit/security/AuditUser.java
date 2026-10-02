package com.github.feng111627.audittrailcomplianceservicejava.audit.security;

import java.util.Set;

/** 当前调用方。 */
public record AuditUser(String username, String displayName, Set<String> roles) {
}

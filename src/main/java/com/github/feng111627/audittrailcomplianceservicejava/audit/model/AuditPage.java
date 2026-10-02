package com.github.feng111627.audittrailcomplianceservicejava.audit.model;

import java.util.List;

public record AuditPage(List<AuditEvent> items, long total, int limit, long offset) {
}

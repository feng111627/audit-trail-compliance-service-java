package com.github.feng111627.audittrailcomplianceservicejava.audit.model;

import java.time.Instant;
import java.util.Map;

/**
 * 一条审计记录。eventId 全局唯一且可重算，用于幂等防重。
 */
public record AuditEvent(
        String eventId,
        String requestId,
        long sequence,
        String actor,
        String action,
        String resourceType,
        String resourceId,
        Map<String, Object> parameters,
        OperationResult result,
        String reason,
        Instant timestamp,
        long durationMillis,
        boolean async
) {
}

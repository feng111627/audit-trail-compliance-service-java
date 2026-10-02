package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.time.Instant;
import java.util.Set;

/**
 * 一条审计记录。
 * 归属关系：traceId 标识一次请求；spanId/parentSpanId 标识操作的嵌套关系；
 * seq 为同一 trace 内的严格递增序号；eventId 全局唯一。
 */
public record AuditEvent(
        String eventId,
        String traceId,
        String spanId,
        String parentSpanId,
        long seq,
        Instant eventTime,
        String actor,
        Set<String> actorRoles,
        String action,
        String resourceType,
        String resourceId,
        AuditOutcome outcome,
        String reasonCode,
        String reasonDetail,
        String params,
        long durationMs,
        String threadName,
        String idempotencyKey
) {
}

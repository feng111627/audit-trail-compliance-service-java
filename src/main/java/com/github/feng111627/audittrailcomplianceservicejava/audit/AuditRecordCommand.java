package com.github.feng111627.audittrailcomplianceservicejava.audit;

/** 切面/业务侧提交一条审计记录时使用的命令对象（params 应为已脱敏文本）。 */
public record AuditRecordCommand(
        String action,
        String resourceType,
        String resourceId,
        String params,
        AuditOutcome outcome,
        String reasonCode,
        String reasonDetail,
        long durationMs
) {
}

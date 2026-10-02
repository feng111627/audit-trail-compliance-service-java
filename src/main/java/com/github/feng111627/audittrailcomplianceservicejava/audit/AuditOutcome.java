package com.github.feng111627.audittrailcomplianceservicejava.audit;

/** 审计事件的结果分类：明确区分成功、业务失败、校验拒绝、越权拒绝与异常中断。 */
public enum AuditOutcome {
    SUCCESS,
    FAILURE,
    VALIDATION_REJECTED,
    ACCESS_DENIED,
    ERROR
}

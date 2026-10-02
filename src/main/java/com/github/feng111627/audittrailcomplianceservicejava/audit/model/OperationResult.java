package com.github.feng111627.audittrailcomplianceservicejava.audit.model;

/** 操作结果：成功 / 业务失败（被拒绝） / 参数校验未通过（被拒绝） / 异常中断。 */
public enum OperationResult {
    SUCCESS,
    FAILED,
    VALIDATION_REJECTED,
    ERROR
}

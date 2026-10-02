package com.github.feng111627.audittrailcomplianceservicejava.audit;

/** 业务失败（操作被业务规则拒绝，但非参数校验或权限问题）。 */
public class BusinessFailureException extends RuntimeException {
    public BusinessFailureException(String message) {
        super(message);
    }
}

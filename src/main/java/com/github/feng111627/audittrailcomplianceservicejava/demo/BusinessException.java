package com.github.feng111627.audittrailcomplianceservicejava.demo;

/** 业务规则被拒绝（区别于系统异常中断）。 */
public class BusinessException extends RuntimeException {
    public BusinessException(String message) {
        super(message);
    }
}

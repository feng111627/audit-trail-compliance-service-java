package com.github.feng111627.audittrailcomplianceservicejava.demo;

/** 下单请求：含手机号、证件号等敏感字段，用于演示脱敏。 */
public record PlaceOrderRequest(String orderId, String customerName, String phone, String idCard) {
}

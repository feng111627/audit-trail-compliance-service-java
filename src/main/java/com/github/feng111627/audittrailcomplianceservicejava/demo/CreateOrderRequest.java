package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive;
import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive.SensitiveType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** 创建订单请求：含手机号与支付密码等敏感字段。 */
public record CreateOrderRequest(
        @NotBlank String owner,
        String product,
        @Sensitive(SensitiveType.PHONE)
        @Pattern(regexp = "^1\\d{10}$", message = "手机号格式不正确") String phone,
        @Sensitive(SensitiveType.PASSWORD)
        @Size(min = 6, message = "支付密码至少6位") String payPassword) {
}

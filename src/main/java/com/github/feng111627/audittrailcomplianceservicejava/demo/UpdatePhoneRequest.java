package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive;
import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive.SensitiveType;
import jakarta.validation.constraints.Pattern;

public record UpdatePhoneRequest(
        @Sensitive(SensitiveType.PHONE)
        @Pattern(regexp = "^1\\d{10}$", message = "手机号格式不正确") String phone) {
}

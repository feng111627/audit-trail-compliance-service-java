package com.github.feng111627.audittrailcomplianceservicejava.audit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注敏感字段/参数，落库与查询前按 type 脱敏。 */
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface Sensitive {
    SensitiveType value();

    enum SensitiveType {
        PASSWORD,
        PHONE,
        ID_CARD
    }
}

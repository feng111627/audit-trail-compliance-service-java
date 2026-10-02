package com.github.feng111627.audittrailcomplianceservicejava.audit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注需要自动留痕的业务方法。 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    /** 操作类型，如 ORDER_CREATE；为空时用 类名.方法名。 */
    String action() default "";

    /** 资源类型，如 ORDER。 */
    String resourceType() default "";

    /**
     * 资源 ID 的 SpEL 表达式，可引用参数名，如 "#id"、"#result.id()"。
     * 为空表示无单一资源 ID。
     */
    String resourceId() default "";

    /** 是否记录入参（脱敏后）。 */
    boolean recordParameters() default true;
}

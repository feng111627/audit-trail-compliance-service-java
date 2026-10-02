package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注需要自动留痕的业务方法。 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {

    String action();

    String resourceType() default "";

    /** 资源标识的 SpEL 表达式（可引用方法参数），为空时不记录资源 id。 */
    String resourceIdExpr() default "";

    /** 是否记录入参（记录前会经过脱敏处理）。 */
    boolean recordParams() default true;
}

package com.github.feng111627.audittrailcomplianceservicejava.audit.masking;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive.SensitiveType;
import java.util.Map;

/** 敏感信息脱敏：落库前与对外查询前统一经过。 */
public interface MaskingService {

    String mask(String raw, SensitiveType type);

    Map<String, Object> maskParameters(Map<String, Object> raw);

    /** 对单个对象（record/bean/集合/Map）按 @Sensitive 与字段名递归脱敏。 */
    Object maskObject(Object value);
}

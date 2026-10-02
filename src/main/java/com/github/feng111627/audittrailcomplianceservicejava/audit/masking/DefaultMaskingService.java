package com.github.feng111627.audittrailcomplianceservicejava.audit.masking;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive;
import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive.SensitiveType;
import java.lang.reflect.Field;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * 默认脱敏实现。
 *
 * <p>规则：
 * <ul>
 *   <li>密码类：统一 ******；</li>
 *   <li>手机号：保留前3后4，如 138****1234；</li>
 *   <li>证件号：保留前6后4，中间星号。</li>
 * </ul>
 * 同时支持依据 {@link Sensitive} 注解对 record/bean/集合/Map 做递归脱敏，
 * 以及按参数名（password/phone/idCard 等）兜底识别。
 */
@Service
public class DefaultMaskingService implements MaskingService {

    @Override
    public String mask(String raw, SensitiveType type) {
        if (raw == null) {
            return null;
        }
        if (type == null) {
            return raw;
        }
        int len = raw.length();
        return switch (type) {
            case PASSWORD -> "******";
            case PHONE -> len <= 7 ? "*".repeat(len) : raw.substring(0, 3) + "****" + raw.substring(len - 4);
            case ID_CARD -> len <= 10 ? "*".repeat(len)
                    : raw.substring(0, 6) + "*".repeat(len - 10) + raw.substring(len - 4);
        };
    }

    @Override
    public Map<String, Object> maskParameters(Map<String, Object> raw) {
        if (raw == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        raw.forEach((key, value) -> out.put(key, maskByName(key, value)));
        return out;
    }

    /** 依据字段/参数名做兜底脱敏。 */
    private Object maskByName(String name, Object value) {
        SensitiveType type = detectByName(name);
        if (type != null && value instanceof String s) {
            return mask(s, type);
        }
        return deepMask(value);
    }

    private SensitiveType detectByName(String name) {
        if (name == null) {
            return null;
        }
        String n = name.toLowerCase();
        if (n.contains("password") || n.contains("passwd") || n.contains("secret")) {
            return SensitiveType.PASSWORD;
        }
        if (n.contains("phone") || n.contains("mobile")) {
            return SensitiveType.PHONE;
        }
        if (n.contains("idcard") || n.contains("idno") || n.contains("certno") || n.contains("idcardno")) {
            return SensitiveType.ID_CARD;
        }
        return null;
    }

    @Override
    public Object maskObject(Object value) {
        return deepMask(value);
    }

    /** 递归脱敏：注解优先，其次结构遍历。 */
    private Object deepMask(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String || value instanceof Number || value instanceof Boolean
                || value instanceof Character || value instanceof Enum<?>) {
            return value;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), maskByName(String.valueOf(k), v)));
            return out;
        }
        if (value instanceof Collection<?> collection) {
            Collection<Object> out = new ArrayList<>(collection.size());
            for (Object item : collection) {
                out.add(deepMask(item));
            }
            return out;
        }
        if (value.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(value);
            Collection<Object> out = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                out.add(deepMask(java.lang.reflect.Array.get(value, i)));
            }
            return out;
        }
        Class<?> clazz = value.getClass();
        if (clazz.isRecord()) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (RecordComponent component : clazz.getRecordComponents()) {
                try {
                    Object componentValue = component.getAccessor().invoke(value);
                    Sensitive ann = component.getAnnotation(Sensitive.class);
                    if (ann != null && componentValue instanceof String s) {
                        out.put(component.getName(), mask(s, ann.value()));
                    } else {
                        out.put(component.getName(), deepMask(componentValue));
                    }
                } catch (ReflectiveOperationException e) {
                    out.put(component.getName(), "<mask-error>");
                }
            }
            return out;
        }
        return maskBean(clazz, value);
    }

    /** 普通 bean：按字段上的 @Sensitive 递归脱敏。 */
    private Object maskBean(Class<?> clazz, Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Field field : clazz.getDeclaredFields()) {
            if (field.isSynthetic()) {
                continue;
            }
            try {
                field.setAccessible(true);
                Object fieldValue = field.get(value);
                Sensitive ann = field.getAnnotation(Sensitive.class);
                if (ann != null && fieldValue instanceof String s) {
                    out.put(field.getName(), mask(s, ann.value()));
                } else {
                    out.put(field.getName(), deepMask(fieldValue));
                }
            } catch (IllegalAccessException e) {
                out.put(field.getName(), "<mask-error>");
            }
        }
        return out;
    }
}

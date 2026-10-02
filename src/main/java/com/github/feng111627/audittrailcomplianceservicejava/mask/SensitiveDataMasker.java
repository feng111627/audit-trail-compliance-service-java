package com.github.feng111627.audittrailcomplianceservicejava.mask;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * 敏感数据脱敏组件。
 *
 * <p>两类规则，缺一不可：
 * <ol>
 *   <li><b>按字段名</b>：字段名包含 {@code password/passwd/pwd/secret/token/密码} 的值整体替换，
 *       防止正则按长度识别不出来；</li>
 *   <li><b>按内容模式</b>：无论敏感内容出现在什么文本里（JSON、异常消息、自由文本），
 *       都扫描替换。</li>
 * </ol>
 *
 * <p>内容规则：
 * <ul>
 *   <li>身份证号（18 位，末位可为 X）：保留前 6 后 4，中间 8 位打码；</li>
 *   <li>手机号（中国大陆 11 位）：保留前 3 后 4，中间 4 位打码。</li>
 * </ul>
 *
 * <p>身份证正则先于手机号执行，避免 18 位证件号中的 11 位子串被手机号规则提前处理。
 */
@Component
public class SensitiveDataMasker {

    /** 18 位身份证：前 6 + 8 个打码 + 后 4（末位 X 保留打码语义时按数字位处理）。 */
    private static final Pattern ID_CARD_18 =
            Pattern.compile("(?<![0-9Xx])([1-9]\\d{5})\\d{8}(\\d{3}[0-9Xx])(?![0-9Xx])");

    /** 15 位老版身份证：保留前 6 后 4。 */
    private static final Pattern ID_CARD_15 =
            Pattern.compile("(?<![0-9])([1-9]\\d{5})\\d{5}(\\d{4})(?![0-9])");

    /** 中国大陆手机号：保留前 3 后 4。 */
    private static final Pattern MOBILE =
            Pattern.compile("(?<![0-9])(1[3-9]\\d)\\d{4}(\\d{4})(?![0-9])");

    private static final String FULL_MASK = "******";

    private static final String[] SENSITIVE_FIELD_HINTS = {
            "password", "passwd", "pwd", "secret", "token", "密码", "口令"
    };

    /**
     * 键值对形式的密码字段，例如 {@code password=abc123}、{@code "pwd":"secret"}、
     * {@code 密码：abc}。仅按内容模式无法识别密码（长度任意），因此单列一条规则，
     * 在内容扫描之前先把这类值整体打码。
     */
    private static final Pattern SECRET_KV = Pattern.compile(
            "(?i)((?:password|passwd|pwd|secret|token|密码|口令)[\"']?\\s*[:=＝：]\\s*[\"']?)"
                    + "[^,;\\s'\"）)]*");

    /** 对任意文本做内容模式脱敏（异常消息、参数 toString、查询返回前的兜底处理）。 */
    public String mask(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw;
        }
        String result = raw;
        Matcher kv = SECRET_KV.matcher(result);
        StringBuilder sb = new StringBuilder(result.length());
        while (kv.find()) {
            kv.appendReplacement(sb, Matcher.quoteReplacement(kv.group(1) + FULL_MASK));
        }
        kv.appendTail(sb);
        result = sb.toString();
        result = ID_CARD_18.matcher(result).replaceAll("$1********$2");
        result = ID_CARD_15.matcher(result).replaceAll("$1*****$2");
        result = maskMobiles(result);
        return result;
    }

    private String maskMobiles(String text) {
        Matcher m = MOBILE.matcher(text);
        StringBuilder sb = new StringBuilder(text.length());
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + "****" + m.group(2)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * 按字段名 + 内容双重脱敏。密码类字段整体打码，其余字段做内容模式扫描。
     */
    public String maskValue(String fieldName, String value) {
        if (value == null) {
            return null;
        }
        if (isSensitiveFieldName(fieldName)) {
            return FULL_MASK;
        }
        return mask(value);
    }

    /** 判断字段名是否属于密码/密钥类（大小写不敏感）。 */
    public boolean isSensitiveFieldName(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        String lower = fieldName.toLowerCase();
        for (String hint : SENSITIVE_FIELD_HINTS) {
            if (lower.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}

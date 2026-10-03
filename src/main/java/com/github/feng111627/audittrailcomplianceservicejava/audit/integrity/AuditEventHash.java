package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

/**
 * 审计记录内容哈希：对记录的规范化表示（字段定序、参数按 key 排序）做 SHA-256，
 * 并把上一环哈希混入，使每一环都依赖之前所有落库记录。
 */
public final class AuditEventHash {

    /** 首环的 previousHash 占位值（64 个 0，形如全零 SHA-256）。 */
    public static final String GENESIS = "0".repeat(64);

    private static final char SEP = '\u0001';

    private AuditEventHash() {
    }

    /** 计算某条记录在指定前驱哈希下的链上哈希。 */
    public static String compute(AuditEvent event, String previousHash) {
        return sha256Hex(canonical(event) + SEP + previousHash);
    }

    /** 记录的规范化串：字段定序拼接，参数按 key 字典序展开，保证可重算。 */
    static String canonical(AuditEvent event) {
        StringBuilder sb = new StringBuilder(256);
        sb.append(event.eventId()).append(SEP)
                .append(event.requestId()).append(SEP)
                .append(event.sequence()).append(SEP)
                .append(event.actor()).append(SEP)
                .append(event.action()).append(SEP)
                .append(event.resourceType()).append(SEP)
                .append(event.resourceId()).append(SEP)
                .append(canonicalParameters(event.parameters())).append(SEP)
                .append(event.result()).append(SEP)
                .append(event.reason()).append(SEP)
                .append(event.timestamp()).append(SEP)
                .append(event.durationMillis()).append(SEP)
                .append(event.async());
        return sb.toString();
    }

    private static String canonicalParameters(Map<String, Object> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        new TreeMap<>(parameters).forEach((k, v) ->
                sb.append(k).append('=').append(String.valueOf(v)).append(','));
        sb.setCharAt(sb.length() - 1, '}');
        return sb.toString();
    }

    private static String sha256Hex(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JDK 不支持 SHA-256", e);
        }
    }
}

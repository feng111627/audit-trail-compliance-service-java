package com.github.feng111627.audittrailcomplianceservicejava.audit.service;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Component;

/**
 * 审计记录哈希计算。对记录内容做确定性规范化序列化后取 SHA-256，
 * 同一内容任何时候重算结果一致，校验侧据此发现内容是否被改动。
 */
@Component
public class HashService {

    /**
     * 计算一条记录的链上哈希：内容哈希再混入 previousHash，
     * 使每条记录与前序记录形成可验证的先后关联（改任意一条，后续全部对不上）。
     */
    public String chainHash(AuditEvent event, String previousHash) {
        return sha256(canonicalContent(event) + "|prev=" + previousHash);
    }

    /** 仅按当前存储内容重算哈希（校验时与 eventHash / anonymizedHash 比对）。 */
    public String contentHash(AuditEvent event, String previousHash) {
        return chainHash(event, previousHash);
    }

    /** 规范化内容：字段定序拼接，Map 按键排序，避免序列化顺序影响结果。 */
    private String canonicalContent(AuditEvent e) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("eventId=").append(e.eventId())
          .append("|requestId=").append(e.requestId())
          .append("|sequence=").append(e.sequence())
          .append("|actor=").append(e.actor())
          .append("|action=").append(e.action())
          .append("|resourceType=").append(e.resourceType())
          .append("|resourceId=").append(e.resourceId())
          .append("|parameters=").append(canonicalParameters(e.parameters()))
          .append("|result=").append(e.result())
          .append("|reason=").append(e.reason())
          .append("|timestamp=").append(e.timestamp())
          .append("|durationMillis=").append(e.durationMillis())
          .append("|async=").append(e.async());
        return sb.toString();
    }

    private String canonicalParameters(Map<String, Object> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return "{}";
        }
        // TreeMap 保证键序确定
        Map<String, Object> sorted = new TreeMap<>(parameters);
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : sorted.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(entry.getKey()).append('=').append(String.valueOf(entry.getValue()));
        }
        return sb.append('}').toString();
    }

    private String sha256(String content) {
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

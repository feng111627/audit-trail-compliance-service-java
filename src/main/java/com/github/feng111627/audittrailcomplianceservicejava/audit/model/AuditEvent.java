package com.github.feng111627.audittrailcomplianceservicejava.audit.model;

import java.time.Instant;
import java.util.Map;

/**
 * 一条审计记录。eventId 全局唯一且可重算，用于幂等防重。
 *
 * <p>防篡改链字段（功能上线后新写入的记录才有）：
 * <ul>
 *   <li>{@code chainIndex}：链内序号，从 0 开始单调递增；历史遗留记录为 -1（未入链）。</li>
 *   <li>{@code previousHash}：前一条入链记录的 eventHash；链首为常量 GENESIS。</li>
 *   <li>{@code eventHash}：本条内容 + previousHash 的 SHA-256，写入后不再变化（匿名化也不改）。</li>
 *   <li>{@code anonymizedHash}：留存策略匿名化后按新内容重算的哈希；未匿名化为 null。
 *       校验时：anonymizedHash 非空则比对它，否则比对 eventHash。</li>
 * </ul>
 */
public record AuditEvent(
        String eventId,
        String requestId,
        long sequence,
        String actor,
        String action,
        String resourceType,
        String resourceId,
        Map<String, Object> parameters,
        OperationResult result,
        String reason,
        Instant timestamp,
        long durationMillis,
        boolean async,
        long chainIndex,
        String previousHash,
        String eventHash,
        String anonymizedHash
) {
    /** 链首记录的 previousHash 取值。 */
    public static final String GENESIS = "GENESIS";

    /** 未入链（历史遗留）记录的 chainIndex。 */
    public static final long LEGACY_CHAIN_INDEX = -1L;

    /**
     * 兼容旧签名：功能上线前的历史记录没有链字段，
     * 以 chainIndex=-1、哈希为 null 表示“历史遗留、未纳入链”，校验时按 LEGACY 处理而非篡改。
     */
    public AuditEvent(
            String eventId,
            String requestId,
            long sequence,
            String actor,
            String action,
            String resourceType,
            String resourceId,
            Map<String, Object> parameters,
            OperationResult result,
            String reason,
            Instant timestamp,
            long durationMillis,
            boolean async
    ) {
        this(eventId, requestId, sequence, actor, action, resourceType, resourceId,
                parameters, result, reason, timestamp, durationMillis, async,
                LEGACY_CHAIN_INDEX, null, null, null);
    }

    /** 是否已纳入防篡改链。 */
    public boolean isChained() {
        return chainIndex >= 0 && eventHash != null;
    }
}

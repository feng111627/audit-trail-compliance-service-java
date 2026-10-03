package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.time.Instant;

/**
 * 防篡改链上的一环：一条审计记录落库后，把“记录内容哈希 + 上一环哈希”
 * 再哈希成本环 entryHash，形成可验证的先后关联（哈希链）。
 *
 * <p>position 从 1 开始单调递增；previousHash 指向前一环的 entryHash，
 * 首环为 {@link AuditEventHash#GENESIS}。链上条目只增不改。
 */
public record ChainEntry(
        long position,
        String eventId,
        Instant eventTimestamp,
        String previousHash,
        String entryHash
) {
}

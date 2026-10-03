package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

/**
 * 一次完整性校验的结果。
 *
 * @param intact            整体是否完整（无任何异常）
 * @param scannedCount      本次扫描的链上记录数
 * @param chainedCount      其中已入链记录数
 * @param legacyCount       范围内历史遗留（未入链）记录数——只统计，不算异常
 * @param purgedCount       命中的正常清理墓碑数（正常留存清理，不算异常）
 * @param anonymizedCount   已匿名化且哈希吻合的记录数
 * @param fromChainIndex    实际校验的链段起点（含）
 * @param toChainIndex      实际校验的链段终点（含）
 * @param anomalyType       第一处异常类型；无异常为 null
 * @param anomalyChainIndex 第一处异常的链上序号；无异常为 null
 * @param anomalyEventId    第一处异常的记录 eventId（记录缺失类异常为 null）
 * @param anomalyMessage    第一处异常的可读描述
 */
public record IntegrityReport(
        boolean intact,
        long scannedCount,
        long chainedCount,
        long legacyCount,
        long purgedCount,
        long anonymizedCount,
        Long fromChainIndex,
        Long toChainIndex,
        AnomalyType anomalyType,
        Long anomalyChainIndex,
        String anomalyEventId,
        String anomalyMessage
) {
    public static IntegrityReport clean(long scannedCount, long chainedCount, long legacyCount,
                                        long purgedCount, long anonymizedCount,
                                        Long fromChainIndex, Long toChainIndex) {
        return new IntegrityReport(true, scannedCount, chainedCount, legacyCount,
                purgedCount, anonymizedCount, fromChainIndex, toChainIndex,
                null, null, null, null);
    }
}

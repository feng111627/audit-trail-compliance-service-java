package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

/**
 * 一次完整性校验的结果。
 *
 * @param intact           范围内是否整体完整（无篡改、无断链）
 * @param verifiedCount    本次通过哈希校验的已入链记录数
 * @param anonymizedCount  其中按留存策略正常匿名化、凭登记哈希通过的记录数
 * @param purgedCount      范围内已被留存策略物理删除并登记的链上环节数（正常清理，不算异常；
 *                         未登记而记录缺失的属于人为删除，报 RECORD_MISSING 异常，不计入本项）
 * @param legacyCount      范围内尚未入链的历史遗留记录数（上线前已存在，不算异常）
 * @param checkedPositions 本次实际检查到的链上环节数（覆盖量）
 * @param firstAnomaly     第一处异常；无异常为 null
 */
public record IntegrityReport(
        boolean intact,
        long verifiedCount,
        long anonymizedCount,
        long purgedCount,
        long legacyCount,
        long checkedPositions,
        FirstAnomaly firstAnomaly
) {
    /** 第一处对不上的位置：链上位置、记录标识、异常类型与说明。 */
    public record FirstAnomaly(
            long position,
            String eventId,
            AnomalyType type,
            String detail
    ) {
    }

    public enum AnomalyType {
        /** 记录内容被改动，重算哈希与链上登记值不一致。 */
        HASH_MISMATCH,
        /** 链上相邻环节的哈希衔接断开（环节被删/换/重排）。 */
        CHAIN_LINK_BROKEN,
        /** 已入链的记录在库里查不到，且未登记为留存策略正常清理：人为整条删除/被换成别的记录。 */
        RECORD_MISSING
    }
}

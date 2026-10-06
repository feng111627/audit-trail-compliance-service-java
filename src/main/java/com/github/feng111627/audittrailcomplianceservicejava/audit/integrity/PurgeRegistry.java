package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

/**
 * 正常清理登记处：留存策略物理删除一条已入链记录前，先在这里登记 eventId。
 *
 * <p>校验时据此把两类“记录已不在”区分开：
 * <ul>
 *   <li>已登记 → 按留存策略正常清理，计入 purgedCount，不算异常；</li>
 *   <li>未登记 → 绕过接口的人为删除，报 RECORD_MISSING 异常并定位。</li>
 * </ul>
 */
public interface PurgeRegistry {

    /** 登记一条被留存策略正常物理删除的记录（同一 eventId 重复登记幂等）。 */
    void registerPurged(String eventId);

    /** 该记录是否由留存策略正常清理。 */
    boolean isPurged(String eventId);
}

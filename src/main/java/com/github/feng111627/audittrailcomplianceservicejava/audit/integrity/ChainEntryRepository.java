package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.List;
import java.util.Optional;

/**
 * 防篡改链条目存储。链上条目只增不改；
 * 生产可替换为数据库实现（event_id、position 上建唯一索引）。
 */
public interface ChainEntryRepository {

    /** 幂等写入：同一 eventId 已入链时返回 false，不重复不覆盖。 */
    boolean saveIfAbsent(ChainEntry entry);

    Optional<ChainEntry> findByEventId(String eventId);

    Optional<ChainEntry> findByPosition(long position);

    /** 按 position 升序取一批，从 fromPosition（含）开始，用于校验时分批流式读取。 */
    List<ChainEntry> findRange(long fromPosition, int limit);

    /** 按记录落库时间范围分页取链上环节（按 position 升序），供按时间范围校验。 */
    List<ChainEntry> findByEventTimestampBetween(java.time.Instant from, java.time.Instant to,
                                                 long offset, int limit);

    /** 当前链尾（position 最大的一环），空链返回 empty。 */
    Optional<ChainEntry> findLatest();

    long count();
}

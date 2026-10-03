package com.github.feng111627.audittrailcomplianceservicejava.audit.repository;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** 审计记录存储。生产可替换为 JPA/ES 实现，本工程提供内存实现。 */
public interface AuditEventRepository {

    /** 幂等写入：eventId 已存在时返回 false，不覆盖不重复。 */
    boolean saveIfAbsent(AuditEvent event);

    Optional<AuditEvent> findByEventId(String eventId);

    List<AuditEvent> query(String requestId, String actor, String action,
                           String resourceType, String resourceId, int limit, long offset);

    long count(String requestId, String actor, String action,
               String resourceType, String resourceId);

    long deleteOlderThan(Instant cutoff);

    /** 将过期记录匿名化（actor 置为 deleted@retention、参数清空），记录本身保留。 */
    long anonymizeOlderThan(Instant cutoff);

    long countAll();

    List<AuditEvent> findAllOrdered(int limit);

    /** 链上序号最大的入链记录（链尾），无入链记录时为空。 */
    Optional<AuditEvent> findLatestChained();

    /** 从某个链上序号起（含）按链序分批取入链记录，供完整性校验流式扫描。 */
    List<AuditEvent> findChainedFrom(long fromChainIndexInclusive, int limit);

    Optional<AuditEvent> findByChainIndex(long chainIndex);

    /** 按过期时间查出记录（留存清理前用于登记墓碑/重算匿名化哈希）。 */
    List<AuditEvent> findOlderThan(Instant cutoff);

    /** 留存匿名化后回写按新内容重算的哈希，eventHash 保持不变。 */
    void updateAnonymizedHash(String eventId, String anonymizedHash);

    /** 时间 >= from 的第一条（链上序号最小）入链记录。 */
    Optional<AuditEvent> findFirstChainedAtOrAfter(Instant from);

    /** 时间 <= to 的最后一条（链上序号最大）入链记录。 */
    Optional<AuditEvent> findLastChainedAtOrBefore(Instant to);

    /** 指定时间范围内未入链的历史遗留记录数（from/to 为 null 表示不限）。 */
    long countLegacy(Instant from, Instant to);
}

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
}

package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.time.Instant;
import java.util.List;

/** 审计记录存储抽象。 */
public interface AuditEventRepository {

    /** 幂等保存：若唯一键已存在则返回已存在的记录，不重复写入。 */
    AuditEvent save(AuditEvent event);

    List<AuditEvent> findAll();

    /** 删除严格早于 cutoff 的记录，返回删除条数。 */
    int deleteOlderThan(Instant cutoff);
}

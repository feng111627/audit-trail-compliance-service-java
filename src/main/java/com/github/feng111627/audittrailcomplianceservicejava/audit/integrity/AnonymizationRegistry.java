package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.Optional;

/**
 * 留存策略匿名化登记处：记录被正常匿名化后，其内容会变（actor 置空、参数清空），
 * 原始链上哈希必然对不上。这里登记“匿名化后的内容哈希”，校验时据此把
 * “按留存策略正常匿名化”与“被篡改”区分开。
 */
public interface AnonymizationRegistry {

    /** 登记某条记录匿名化后的内容哈希（同一 eventId 重复登记以首次为准）。 */
    void register(String eventId, String anonymizedHash);

    Optional<String> findAnonymizedHash(String eventId);
}

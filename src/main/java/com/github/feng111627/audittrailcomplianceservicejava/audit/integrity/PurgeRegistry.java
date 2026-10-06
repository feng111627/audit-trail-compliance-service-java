package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

/**
 * 留存策略物理删除登记处：记录被留存策略正常删除后，其链上环节仍在、
 * 记录本体已不在。这里登记“哪些 eventId 是按留存策略删的”，校验时据此把
 * “到点正常清理”与“绕过接口的人为删除”区分开——后者必须报异常，前者不算。
 */
public interface PurgeRegistry {

    /** 登记某条记录已被留存策略物理删除（同一 eventId 重复登记幂等）。 */
    void registerPurged(String eventId);

    /** 该记录是否由留存策略正常删除。 */
    boolean isPurged(String eventId);
}

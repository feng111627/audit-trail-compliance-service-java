package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/** 内存版留存删除登记处（演示/本地验证用）。 */
@Repository
public class InMemoryPurgeRegistry implements PurgeRegistry {

    private final Set<String> purgedIds = ConcurrentHashMap.newKeySet();

    @Override
    public void registerPurged(String eventId) {
        purgedIds.add(eventId);
    }

    @Override
    public boolean isPurged(String eventId) {
        return purgedIds.contains(eventId);
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/** 线程安全的内存墓碑存储（演示/本地验证用）。 */
@Repository
public class InMemoryPurgeTombstoneStore implements PurgeTombstoneStore {

    private final ConcurrentHashMap<Long, String> tombstones = new ConcurrentHashMap<>();

    @Override
    public void put(long chainIndex, String eventHash) {
        tombstones.putIfAbsent(chainIndex, eventHash);
    }

    @Override
    public Optional<String> findHash(long chainIndex) {
        return Optional.ofNullable(tombstones.get(chainIndex));
    }

    @Override
    public long count() {
        return tombstones.size();
    }
}

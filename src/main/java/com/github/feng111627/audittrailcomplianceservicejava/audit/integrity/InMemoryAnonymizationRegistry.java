package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/** 内存版匿名化登记处（演示/本地验证用）。 */
@Repository
public class InMemoryAnonymizationRegistry implements AnonymizationRegistry {

    private final ConcurrentHashMap<String, String> hashes = new ConcurrentHashMap<>();

    @Override
    public void register(String eventId, String anonymizedHash) {
        hashes.putIfAbsent(eventId, anonymizedHash);
    }

    @Override
    public Optional<String> findAnonymizedHash(String eventId) {
        return Optional.ofNullable(hashes.get(eventId));
    }
}

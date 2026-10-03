package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import org.springframework.stereotype.Repository;

/** 线程安全的内存链存储（演示/本地验证用）。 */
@Repository
public class InMemoryChainEntryRepository implements ChainEntryRepository {

    private final ConcurrentSkipListMap<Long, ChainEntry> byPosition = new ConcurrentSkipListMap<>();
    private final ConcurrentHashMap<String, ChainEntry> byEventId = new ConcurrentHashMap<>();

    @Override
    public boolean saveIfAbsent(ChainEntry entry) {
        // 以 eventId 为幂等键；position 由写入方在锁内分配，不会冲突。
        if (byEventId.putIfAbsent(entry.eventId(), entry) != null) {
            return false;
        }
        byPosition.put(entry.position(), entry);
        return true;
    }

    @Override
    public Optional<ChainEntry> findByEventId(String eventId) {
        return Optional.ofNullable(byEventId.get(eventId));
    }

    @Override
    public Optional<ChainEntry> findByPosition(long position) {
        return Optional.ofNullable(byPosition.get(position));
    }

    @Override
    public List<ChainEntry> findRange(long fromPosition, int limit) {
        return byPosition.tailMap(fromPosition, true).values().stream()
                .limit(Math.max(1, limit))
                .toList();
    }

    @Override
    public List<ChainEntry> findByEventTimestampBetween(java.time.Instant from, java.time.Instant to,
                                                        long offset, int limit) {
        List<ChainEntry> matched = byPosition.values().stream()
                .filter(e -> !e.eventTimestamp().isBefore(from) && !e.eventTimestamp().isAfter(to))
                .toList();
        int safeLimit = Math.max(1, limit);
        long safeOffset = Math.max(0, offset);
        int fromIdx = (int) Math.min(safeOffset, matched.size());
        int toIdx = (int) Math.min(fromIdx + safeLimit, matched.size());
        return matched.subList(fromIdx, toIdx);
    }

    @Override
    public Optional<ChainEntry> findLatest() {
        return byPosition.isEmpty() ? Optional.empty()
                : Optional.of(byPosition.lastEntry().getValue());
    }

    @Override
    public long count() {
        return byPosition.size();
    }
}

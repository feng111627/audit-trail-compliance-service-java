package com.github.feng111627.audittrailcomplianceservicejava.audit.repository;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/**
 * 线程安全的内存仓储（演示/本地验证用）。
 * 生产环境替换为基于唯一索引 event_id 的数据库实现即可，saveIfAbsent 语义对应 insert-if-not-exists。
 */
@Repository
public class InMemoryAuditEventRepository implements AuditEventRepository {

    private final ConcurrentHashMap<String, AuditEvent> store = new ConcurrentHashMap<>();

    @Override
    public boolean saveIfAbsent(AuditEvent event) {
        return store.putIfAbsent(event.eventId(), event) == null;
    }

    @Override
    public Optional<AuditEvent> findByEventId(String eventId) {
        return Optional.ofNullable(store.get(eventId));
    }

    @Override
    public List<AuditEvent> query(String requestId, String actor, String action,
                                  String resourceType, String resourceId, int limit, long offset) {
        List<AuditEvent> matched = matched(requestId, actor, action, resourceType, resourceId);
        return page(matched, limit, offset);
    }

    @Override
    public long count(String requestId, String actor, String action,
                      String resourceType, String resourceId) {
        return matched(requestId, actor, action, resourceType, resourceId).size();
    }

    private List<AuditEvent> matched(String requestId, String actor, String action,
                                     String resourceType, String resourceId) {
        return store.values().stream()
                .filter(e -> requestId == null || requestId.equals(e.requestId()))
                .filter(e -> actor == null || actor.equals(e.actor()))
                .filter(e -> action == null || action.equals(e.action()))
                .filter(e -> resourceType == null || resourceType.equals(e.resourceType()))
                .filter(e -> resourceId == null || resourceId.equals(e.resourceId()))
                .sorted(Comparator.comparing(AuditEvent::timestamp)
                        .thenComparing(AuditEvent::requestId)
                        .thenComparingLong(AuditEvent::sequence))
                .toList();
    }

    private List<AuditEvent> page(List<AuditEvent> ordered, int limit, long offset) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        long safeOffset = Math.max(0, offset);
        int from = (int) Math.min(safeOffset, ordered.size());
        int to = (int) Math.min(from + safeLimit, ordered.size());
        return ordered.subList(from, to);
    }

    @Override
    public long deleteOlderThan(Instant cutoff) {
        List<String> expiredIds = store.values().stream()
                .filter(e -> e.timestamp().isBefore(cutoff))
                .map(AuditEvent::eventId)
                .toList();
        long removed = 0;
        for (String id : expiredIds) {
            if (store.remove(id) != null) {
                removed++;
            }
        }
        return removed;
    }

    @Override
    public long anonymizeOlderThan(Instant cutoff) {
        long count = 0;
        for (AuditEvent event : store.values()) {
            if (event.timestamp().isBefore(cutoff)) {
                AuditEvent anonymized = new AuditEvent(
                        event.eventId(), event.requestId(), event.sequence(),
                        "deleted@retention", event.action(), event.resourceType(),
                        event.resourceId(), Map.of(), event.result(),
                        event.reason() == null ? null : "expired:" + event.reason(),
                        event.timestamp(), event.durationMillis(), event.async());
                store.put(event.eventId(), anonymized);
                count++;
            }
        }
        return count;
    }

    @Override
    public long countAll() {
        return store.size();
    }

    @Override
    public List<AuditEvent> findAllOrdered(int limit) {
        return store.values().stream()
                .sorted(Comparator.comparing(AuditEvent::timestamp)
                        .thenComparing(AuditEvent::requestId)
                        .thenComparingLong(AuditEvent::sequence))
                .limit(Math.max(1, Math.min(limit, 500)))
                .toList();
    }
}

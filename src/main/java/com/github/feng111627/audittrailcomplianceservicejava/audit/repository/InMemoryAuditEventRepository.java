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
    public List<String> deleteOlderThan(Instant cutoff) {
        List<String> expiredIds = store.values().stream()
                .filter(e -> e.timestamp().isBefore(cutoff))
                .map(AuditEvent::eventId)
                .toList();
        List<String> removed = new java.util.ArrayList<>();
        for (String id : expiredIds) {
            if (store.remove(id) != null) {
                removed.add(id);
            }
        }
        return removed;
    }

    @Override
    public List<AuditEvent> anonymizeOlderThan(Instant cutoff) {
        List<AuditEvent> anonymizedEvents = new java.util.ArrayList<>();
        for (AuditEvent event : store.values()) {
            if (event.timestamp().isBefore(cutoff)) {
                AuditEvent anonymized = new AuditEvent(
                        event.eventId(), event.requestId(), event.sequence(),
                        "deleted@retention", event.action(), event.resourceType(),
                        event.resourceId(), Map.of(), event.result(),
                        event.reason() == null ? null : "expired:" + event.reason(),
                        event.timestamp(), event.durationMillis(), event.async());
                store.put(event.eventId(), anonymized);
                anonymizedEvents.add(anonymized);
            }
        }
        return anonymizedEvents;
    }

    @Override
    public long countAll() {
        return store.size();
    }

    /**
     * 模拟“绕过接口直接改库”的覆盖写：仅用于测试/演示防篡改校验，
     * 正常业务路径不会调用（接口本身也不暴露此方法）。
     */
    public void forceReplace(AuditEvent event) {
        store.put(event.eventId(), event);
    }

    /**
     * 模拟“绕过接口直接删库”的物理删除：仅用于测试/演示防篡改校验，
     * 正常业务路径不会调用（留存清理走 deleteOlderThan 并做登记）。
     */
    public void forceDelete(String eventId) {
        store.remove(eventId);
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

    @Override
    public List<AuditEvent> findByTimestampBetween(Instant from, Instant to, long offset, int limit) {
        List<AuditEvent> matched = store.values().stream()
                .filter(e -> !e.timestamp().isBefore(from) && !e.timestamp().isAfter(to))
                .sorted(Comparator.comparing(AuditEvent::timestamp)
                        .thenComparing(AuditEvent::requestId)
                        .thenComparingLong(AuditEvent::sequence))
                .toList();
        int safeLimit = Math.max(1, Math.min(limit, 500));
        long safeOffset = Math.max(0, offset);
        int fromIdx = (int) Math.min(safeOffset, matched.size());
        int toIdx = (int) Math.min(fromIdx + safeLimit, matched.size());
        return matched.subList(fromIdx, toIdx);
    }
}

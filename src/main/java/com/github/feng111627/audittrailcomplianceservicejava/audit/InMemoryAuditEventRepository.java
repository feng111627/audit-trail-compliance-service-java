package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Repository;

/**
 * 基于内存的审计存储，线程安全。
 *
 * <p><b>幂等键</b>：同一请求携带同一 {@code Idempotency-Key} 时，对同一 action 的重复写入
 * （重试、切面重入等）不会产生重复记录——键为 {@code idempotencyKey + "::" + action}；
 * 没有幂等键时使用全局唯一 eventId 去重。
 *
 * <p>生产环境可替换为数据库唯一索引实现，接口保持不变。
 */
@Repository
public class InMemoryAuditEventRepository implements AuditEventRepository {

    private final ConcurrentMap<String, AuditEvent> store = new ConcurrentHashMap<>();

    private static String dedupeKey(AuditEvent event) {
        if (event.idempotencyKey() != null && !event.idempotencyKey().isBlank()) {
            return "IDEM:" + event.idempotencyKey() + "::" + event.action();
        }
        return "EVT:" + event.eventId();
    }

    @Override
    public AuditEvent save(AuditEvent event) {
        // putIfAbsent 原子操作：并发/重试情况下只有第一次写入生效，其余返回已存在记录。
        AuditEvent existing = store.putIfAbsent(dedupeKey(event), event);
        return existing != null ? existing : event;
    }

    @Override
    public List<AuditEvent> findAll() {
        // 同一 trace 内按 seq 排序；跨请求按事件时间排序，保证先后关系可读。
        return store.values().stream()
                .sorted(Comparator.comparing(AuditEvent::eventTime)
                        .thenComparing(AuditEvent::traceId)
                        .thenComparingLong(AuditEvent::seq))
                .toList();
    }

    @Override
    public int deleteOlderThan(Instant cutoff) {
        int[] removed = {0};
        store.entrySet().removeIf(e -> {
            if (e.getValue().eventTime().isBefore(cutoff)) {
                removed[0]++;
                return true;
            }
            return false;
        });
        return removed[0];
    }
}

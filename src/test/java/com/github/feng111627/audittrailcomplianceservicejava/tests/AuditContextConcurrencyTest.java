package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.AuditService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 业务点：
 * 1) 并发的多个请求各自归属、互不串号、序列号无重复；
 * 2) 异步线程通过快照继承 requestId，async 标记为 true；
 * 3) 同一次操作“重试”重复写入不会产生重复记录（幂等）。
 */
@SpringBootTest
@DisplayName("业务点-并发与异步下的归属")
class AuditContextConcurrencyTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditEventRepository repository;

    @Test
    @DisplayName("多线程模拟多个并发请求：每个 requestId 独立计数、事件不串请求")
    void concurrentRequestsAreIsolated() throws Exception {
        int requestCount = 12;
        int opsPerRequest = 20;
        ExecutorService pool = Executors.newFixedThreadPool(6);
        List<Future<?>> futures = new ArrayList<>();

        for (int r = 0; r < requestCount; r++) {
            String requestId = "conc-req-" + r + "-" + UUID.randomUUID();
            futures.add(pool.submit(() -> {
                AuditContext.beginRequest(requestId);
                try {
                    for (int i = 0; i < opsPerRequest; i++) {
                        auditService.record("user-" + requestId, "OP", "RES",
                                "res-" + i, null, OperationResult.SUCCESS, null);
                    }
                } finally {
                    AuditContext.endRequest();
                }
            }));
        }
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        List<AuditEvent> all = repository.query(null, null, null, null, null, 10000, 0);
        for (int r = 0; r < requestCount; r++) {
            final int idx = r;
            List<AuditEvent> mine = all.stream()
                    .filter(e -> e.requestId().startsWith("conc-req-" + idx + "-"))
                    .toList();
            assertThat(mine).hasSize(opsPerRequest);
            assertThat(mine).allSatisfy(e ->
                    assertThat(e.actor()).startsWith("user-conc-req-" + idx + "-"));
            List<Long> sequences = mine.stream().map(AuditEvent::sequence).toList();
            assertThat(sequences).doesNotHaveDuplicates();
            assertThat(sequences).containsExactlyInAnyOrderElementsOf(
                    range1(opsPerRequest));
        }
    }

    private List<Long> range1(int n) {
        List<Long> list = new ArrayList<>();
        for (long i = 1; i <= n; i++) {
            list.add(i);
        }
        return list;
    }

    @Test
    @DisplayName("异步线程继承请求上下文：记录归属原 requestId，序列号连续，async=true")
    void asyncThreadInheritsContext() throws Exception {
        String requestId = "async-req-" + UUID.randomUUID();
        AuditContext.beginRequest(requestId);
        try {
            auditService.record("alice", "MAIN_BEFORE", "RES", null,
                    null, OperationResult.SUCCESS, null);

            AuditContext.Snapshot snapshot = AuditContext.snapshot();
            ExecutorService single = Executors.newSingleThreadExecutor();
            Future<?> future = single.submit(AuditContext.wrap((Runnable) () ->
                    auditService.record("alice", "ASYNC_OP", "RES", null,
                            null, OperationResult.SUCCESS, null)));
            future.get(10, TimeUnit.SECONDS);
            single.shutdown();

            auditService.record("alice", "MAIN_AFTER", "RES", null,
                    null, OperationResult.SUCCESS, null);
        } finally {
            AuditContext.endRequest();
        }

        List<AuditEvent> mine = repository.query(requestId, null, null, null, null, 100, 0);
        assertThat(mine).hasSize(3);
        assertThat(mine).extracting(AuditEvent::action)
                .containsExactly("MAIN_BEFORE", "ASYNC_OP", "MAIN_AFTER");
        assertThat(mine).filteredOn(e -> e.action().equals("ASYNC_OP"))
                .singleElement().satisfies(e -> assertThat(e.async()).isTrue());
        assertThat(mine).extracting(AuditEvent::sequence)
                .containsExactly(1L, 2L, 3L);
    }

    @Test
    @DisplayName("相同 requestId+序列号的重复写入（模拟重试）只落库一次")
    void duplicateWriteIsIdempotent() {
        String requestId = "idem-req-" + UUID.randomUUID();
        AuditContext.beginRequest(requestId);
        AuditEvent first;
        AuditEvent second;
        try {
            first = auditService.record("alice", "IDEMPOTENT_OP", "RES", "r1",
                    null, OperationResult.SUCCESS, null);
            // 序列号已前进，无法构造“同序列号”记录；直接对同一 eventId 再写验证仓储幂等
            second = new AuditEvent(first.eventId(), first.requestId(), first.sequence(),
                    first.actor(), first.action(), first.resourceType(), first.resourceId(),
                    first.parameters(), first.result(), first.reason(), first.timestamp(),
                    first.durationMillis(), first.async());
        } finally {
            AuditContext.endRequest();
        }
        boolean insertedAgain = repository.saveIfAbsent(second);
        assertThat(insertedAgain).isFalse();
        long count = repository.query(requestId, null, "IDEMPOTENT_OP", null, null, 10, 0).size();
        assertThat(count).isEqualTo(1);
    }
}

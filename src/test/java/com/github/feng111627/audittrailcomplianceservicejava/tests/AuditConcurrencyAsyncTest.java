package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContextHolder;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditOutcome;
import com.github.feng111627.audittrailcomplianceservicejava.audit.UserContext;
import com.github.feng111627.audittrailcomplianceservicejava.demo.DemoOrderService;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/** 并发与异步场景：归属隔离、幂等去重、异步线程上下文透传。 */
@SpringBootTest
@DisplayName("并发与异步：归属不串、写入不重、异步上下文可透传")
class AuditConcurrencyAsyncTest {

    @Autowired
    private DemoOrderService orderService;

    @Autowired
    private AuditEventRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteOlderThan(Instant.now().plusSeconds(1));
    }

    @Test
    @DisplayName("两个请求并发执行：各自记录只属于自己的 traceId，互不串扰")
    void 并发请求trace归属隔离() throws Exception {
        int threads = 16;
        int perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        Set<String> traceIds = ConcurrentHashMap.newKeySet();

        for (int t = 0; t < threads; t++) {
            final String trace = "trace-" + t;
            pool.submit(() -> {
                try {
                    start.await();
                    AuditContext ctx = new AuditContext(
                            trace, "span-" + trace,
                            new UserContext("user" + trace, Set.of("USER")), null);
                    AuditContextHolder.set(ctx);
                    for (int i = 0; i < perThread; i++) {
                        orderService.cancelOrder("O-" + trace + "-" + i);
                    }
                    traceIds.add(trace);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    AuditContextHolder.clear();
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        List<AuditEvent> all = repository.findAll();
        assertEquals(threads * perThread, all.size(), "全部操作都应留痕");
        assertEquals(threads, traceIds.size());
        // 每条记录的 traceId 必须与操作所属请求一致，不能出现别的请求 id
        for (int t = 0; t < threads; t++) {
            String trace = "trace-" + t;
            List<AuditEvent> mine = all.stream().filter(e -> trace.equals(e.traceId())).toList();
            assertEquals(perThread, mine.size(), "trace " + trace + " 的记录数");
            assertTrue(mine.stream().allMatch(e -> e.actor().equals("user" + trace)));
            assertTrue(mine.stream().allMatch(e -> e.resourceId().startsWith("O-" + trace + "-")));
        }
    }

    @Test
    @DisplayName("同一 Idempotency-Key 下同一动作并发/重试只写一条，不产生重复记录")
    void 幂等键去重() throws Exception {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    // 模拟同一请求在多线程/重试场景重复执行
                    AuditContextHolder.set(AuditContext.startNew(
                            new UserContext("retry-user", Set.of("USER")), "same-key-42"));
                    orderService.cancelOrder("O-IDEM-1");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    AuditContextHolder.clear();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        List<AuditEvent> all = repository.findAll().stream()
                .filter(e -> "ORDER_CANCEL".equals(e.action())).toList();
        assertEquals(1, all.size(), "同一幂等键 + 同一动作只能有一条记录");
        assertEquals("same-key-42", all.get(0).idempotencyKey());
    }

    @Test
    @DisplayName("不同幂等键的同一动作各自保留，去重不会误伤正常请求")
    void 不同幂等键不去重() {
        AuditContextHolder.set(AuditContext.startNew(new UserContext("u1", Set.of()), "key-a"));
        orderService.cancelOrder("O-A");
        AuditContextHolder.clear();
        AuditContextHolder.set(AuditContext.startNew(new UserContext("u2", Set.of()), "key-b"));
        orderService.cancelOrder("O-A");
        AuditContextHolder.clear();

        assertEquals(2, repository.findAll().size());
    }

    @Test
    @DisplayName("@Async 异步操作：审计记录与原请求同 traceId，且执行线程名不同")
    void 异步线程上下文正确透传() throws Exception {
        AuditContext ctx = AuditContext.startNew(new UserContext("async-user", Set.of("USER")), null);
        AuditContextHolder.set(ctx);
        String traceId = ctx.traceId();
        try {
            orderService.processAsync("O-ASYNC-1");
        } finally {
            AuditContextHolder.clear();
        }

        // 等待异步线程中的审计落库（@Async + 切面）
        AuditEvent asyncEvent = waitForEvent("ORDER_ASYNC_PROCESS", 10_000);
        assertNotNull(asyncEvent);
        assertEquals(traceId, asyncEvent.traceId(), "异步记录必须归属原请求 trace");
        assertEquals("async-user", asyncEvent.actor(), "操作人要透传到异步线程");
        assertNotEquals(Thread.currentThread().getName(), asyncEvent.threadName(),
                "记录应确实来自异步工作线程");
        assertTrue(asyncEvent.threadName().startsWith("audit-async-"),
                "异步线程名实际为: " + asyncEvent.threadName());
        assertEquals(AuditOutcome.SUCCESS, asyncEvent.outcome());
        assertNotNull(asyncEvent.parentSpanId(), "异步根 span 的父 span 应指向主线程 span");
    }

    @Test
    @DisplayName("异步线程内的校验失败同样留痕（VALIDATION_REJECTED），且归属原 trace")
    void 异步线程内失败也留痕() throws Exception {
        AuditContext ctx = AuditContext.startNew(new UserContext("async-user2", Set.of()), null);
        AuditContextHolder.set(ctx);
        String traceId = ctx.traceId();
        try {
            orderService.processAsync(" ");
        } finally {
            AuditContextHolder.clear();
        }
        AuditEvent e = waitForEvent("ORDER_ASYNC_PROCESS", 10_000);
        assertEquals(traceId, e.traceId());
        assertEquals(AuditOutcome.VALIDATION_REJECTED, e.outcome());
    }

    private AuditEvent waitForEvent(String action, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            List<AuditEvent> found = repository.findAll().stream()
                    .filter(e -> action.equals(e.action())).toList();
            if (!found.isEmpty()) {
                return found.get(0);
            }
            Thread.sleep(50);
        }
        return null;
    }
}

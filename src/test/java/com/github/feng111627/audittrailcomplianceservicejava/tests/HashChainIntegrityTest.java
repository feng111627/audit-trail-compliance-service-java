package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.feng111627.audittrailcomplianceservicejava.audit.config.AuditProperties;
import com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.AnomalyType;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.HashChainService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryPurgeTombstoneStore;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityVerificationService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.DefaultMaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.InMemoryAuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.DefaultAuditService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.HashService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 业务点：防篡改哈希链与完整性校验。
 * 并发/重试下链不乱；内容被改、记录被删能检出并定位到第一处；
 * 历史遗留记录与正常留存清理（删除/匿名化）不误报。
 */
@DisplayName("业务点-防篡改链与完整性校验")
class HashChainIntegrityTest {

    private InMemoryAuditEventRepository repo;
    private InMemoryPurgeTombstoneStore tombstones;
    private HashChainService chainService;
    private IntegrityVerificationService verifyService;
    private DefaultAuditService auditService;
    private AuditProperties properties;

    @BeforeEach
    void setUp() {
        repo = new InMemoryAuditEventRepository();
        tombstones = new InMemoryPurgeTombstoneStore();
        HashService hashService = new HashService();
        chainService = new HashChainService(repo, hashService);
        verifyService = new IntegrityVerificationService(repo, tombstones, hashService, chainService);
        properties = new AuditProperties();
        auditService = new DefaultAuditService(repo, new DefaultMaskingService(),
                new AuditAccessControl(), properties, chainService, tombstones, hashService);
    }

    private AuditEvent record(String actor, String action) {
        return auditService.record(actor, action, "ORDER", "ORD-1",
                Map.of("phone", "13812341234"), OperationResult.SUCCESS, null);
    }

    @Test
    @DisplayName("多线程并发写入：链上序号连续无重复、关联不乱，校验完整")
    void concurrentWritesKeepChainConsistent() throws Exception {
        int threads = 8;
        int perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Throwable> failures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int threadNo = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        record("user-" + threadNo, "ACTION_" + i);
                    }
                } catch (Throwable e) {
                    synchronized (failures) {
                        failures.add(e);
                    }
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        assertThat(failures).isEmpty();

        int total = threads * perThread;
        assertThat(repo.countAll()).isEqualTo(total);
        // 链上序号恰好覆盖 0..total-1，无重复无缺口
        List<Long> indices = repo.findChainedFrom(0, total).stream()
                .map(AuditEvent::chainIndex).sorted().toList();
        assertThat(indices).hasSize(total);
        assertThat(indices).isEqualTo(java.util.stream.LongStream.range(0, total).boxed().toList());

        IntegrityReport report = verifyService.verify(null, null, null, null);
        assertThat(report.intact()).as("并发写入后整链应完整: %s", report.anomalyMessage()).isTrue();
        assertThat(report.chainedCount()).isEqualTo(total);
    }

    @Test
    @DisplayName("同一请求标识重试：只落库一次，链不重复推进、不断链")
    void retryWithSameRequestIdDoesNotDuplicateOrBreakChain() {
        AuditContext.beginRequest("req-retry");
        AuditEvent first;
        try {
            first = record("alice", "ORDER_CREATE");
        } finally {
            AuditContext.endRequest();
        }
        // 调用方拿同一个 requestId 重试同一操作（序列号重新从 1 开始 -> 同一 eventId）
        AuditContext.beginRequest("req-retry");
        AuditEvent retried;
        try {
            retried = record("alice", "ORDER_CREATE");
        } finally {
            AuditContext.endRequest();
        }

        assertThat(retried.eventId()).isEqualTo(first.eventId());
        assertThat(repo.countAll()).isEqualTo(1);
        assertThat(chainService.currentTailIndex()).isEqualTo(0);

        // 再写一条新记录，链应接在唯一那条之后
        AuditEvent next = record("bob", "ORDER_QUERY");
        assertThat(next.chainIndex()).isEqualTo(1);
        assertThat(next.previousHash()).isEqualTo(first.eventHash());

        IntegrityReport report = verifyService.verify(null, null, null, null);
        assertThat(report.intact()).as(report.anomalyMessage()).isTrue();
        assertThat(report.chainedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("绕过接口改库：内容被改动能检出，并定位到被改的那一条")
    void tamperedContentIsDetectedAndLocated() {
        for (int i = 0; i < 5; i++) {
            record("alice", "ACTION_" + i);
        }
        AuditEvent victim = repo.findByChainIndex(2).orElseThrow();
        // 模拟绕过接口直接改库：把操作人 alice 改成 mallory，链字段原样保留
        AuditEvent tampered = new AuditEvent(
                victim.eventId(), victim.requestId(), victim.sequence(),
                "mallory", victim.action(), victim.resourceType(), victim.resourceId(),
                victim.parameters(), victim.result(), victim.reason(),
                victim.timestamp(), victim.durationMillis(), victim.async(),
                victim.chainIndex(), victim.previousHash(), victim.eventHash(),
                victim.anonymizedHash());
        repo.unsafeReplace(tampered);

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).isFalse();
        assertThat(report.anomalyType()).isEqualTo(AnomalyType.CONTENT_TAMPERED);
        assertThat(report.anomalyChainIndex()).isEqualTo(2);
        assertThat(report.anomalyEventId()).isEqualTo(victim.eventId());
        assertThat(report.anomalyMessage()).contains(victim.eventId());
    }

    @Test
    @DisplayName("绕过接口删库：中间记录被人为删除能检出，并定位到缺失的链上序号")
    void deletedRecordIsDetectedAndLocated() {
        for (int i = 0; i < 5; i++) {
            record("alice", "ACTION_" + i);
        }
        AuditEvent victim = repo.findByChainIndex(3).orElseThrow();
        repo.unsafeDelete(victim.eventId());

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).isFalse();
        assertThat(report.anomalyType()).isEqualTo(AnomalyType.RECORD_MISSING);
        assertThat(report.anomalyChainIndex()).isEqualTo(3);
    }

    @Test
    @DisplayName("绕过接口删链尾：尾部被截断能检出")
    void truncatedTailIsDetected() {
        for (int i = 0; i < 3; i++) {
            record("alice", "ACTION_" + i);
        }
        AuditEvent tail = repo.findByChainIndex(2).orElseThrow();
        repo.unsafeDelete(tail.eventId());

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).isFalse();
        assertThat(report.anomalyType()).isEqualTo(AnomalyType.RECORD_MISSING);
        assertThat(report.anomalyChainIndex()).isEqualTo(2);
        assertThat(report.anomalyMessage()).contains("截断");
    }

    @Test
    @DisplayName("历史遗留记录（无链字段）只统计为 legacy，不误报为篡改")
    void legacyRecordsAreNotReportedAsTampered() {
        // 功能上线前的历史记录：没有链字段，直接落库
        repo.saveIfAbsent(new AuditEvent("legacy-1", "req-old-1", 1, "alice", "ORDER_CREATE",
                "ORDER", "ORD-0", Map.of(), OperationResult.SUCCESS, null,
                Instant.now().minus(10, ChronoUnit.DAYS), 0, false));
        repo.saveIfAbsent(new AuditEvent("legacy-2", "req-old-2", 1, "bob", "ORDER_QUERY",
                "ORDER", "ORD-0", Map.of(), OperationResult.SUCCESS, null,
                Instant.now().minus(9, ChronoUnit.DAYS), 0, false));
        // 上线后的新记录正常入链
        record("alice", "ORDER_CREATE");
        record("bob", "ORDER_QUERY");

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).as(report.anomalyMessage()).isTrue();
        assertThat(report.legacyCount()).isEqualTo(2);
        assertThat(report.chainedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("DELETE 留存清理：正常删除的入链记录登记墓碑，校验不误报")
    void retentionDeleteDoesNotBreakVerification() {
        // 两条“很旧”的入链记录 + 一条新记录
        chainService.append(oldEvent("evt-old-1"));
        chainService.append(oldEvent("evt-old-2"));
        record("alice", "ORDER_CREATE");

        properties.getRetention().setPurgeMode("DELETE");
        properties.getRetention().setDays(30);
        long purged = auditService.purgeExpired();
        assertThat(purged).isEqualTo(2);
        assertThat(tombstones.count()).isEqualTo(2);

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).as(report.anomalyMessage()).isTrue();
        assertThat(report.purgedCount()).isEqualTo(2);
        assertThat(report.chainedCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("ANONYMIZE 留存清理：匿名化记录哈希重算，校验不误报且统计匿名化条数")
    void retentionAnonymizeDoesNotBreakVerification() {
        chainService.append(oldEvent("evt-old-1"));
        chainService.append(oldEvent("evt-old-2"));
        record("alice", "ORDER_CREATE");

        properties.getRetention().setPurgeMode("ANONYMIZE");
        properties.getRetention().setDays(30);
        long purged = auditService.purgeExpired();
        assertThat(purged).isEqualTo(2);

        AuditEvent anonymized = repo.findByEventId("evt-old-1").orElseThrow();
        assertThat(anonymized.actor()).isEqualTo("deleted@retention");
        assertThat(anonymized.anonymizedHash()).isNotNull();
        // eventHash 不变，链关联保持
        assertThat(anonymized.eventHash()).isNotNull();

        IntegrityReport report = verifyService.verify(null, null, null, null);

        assertThat(report.intact()).as(report.anomalyMessage()).isTrue();
        assertThat(report.anonymizedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("按链上序号范围校验：只覆盖指定链段，范围外的篡改不影响本次结论")
    void verifyByChainIndexRange() {
        for (int i = 0; i < 6; i++) {
            record("alice", "ACTION_" + i);
        }
        // 篡改序号 1（在待校验范围之外）
        AuditEvent victim = repo.findByChainIndex(1).orElseThrow();
        repo.unsafeReplace(new AuditEvent(
                victim.eventId(), victim.requestId(), victim.sequence(),
                "mallory", victim.action(), victim.resourceType(), victim.resourceId(),
                victim.parameters(), victim.result(), victim.reason(),
                victim.timestamp(), victim.durationMillis(), victim.async(),
                victim.chainIndex(), victim.previousHash(), victim.eventHash(),
                victim.anonymizedHash()));

        IntegrityReport outOfScope = verifyService.verify(null, null, 3L, 5L);
        assertThat(outOfScope.intact()).as(outOfScope.anomalyMessage()).isTrue();
        assertThat(outOfScope.chainedCount()).isEqualTo(3);
        assertThat(outOfScope.fromChainIndex()).isEqualTo(3);
        assertThat(outOfScope.toChainIndex()).isEqualTo(5);

        IntegrityReport inScope = verifyService.verify(null, null, 0L, 5L);
        assertThat(inScope.intact()).isFalse();
        assertThat(inScope.anomalyType()).isEqualTo(AnomalyType.CONTENT_TAMPERED);
        assertThat(inScope.anomalyChainIndex()).isEqualTo(1);
    }

    @Test
    @DisplayName("按时间范围校验：覆盖该时间段记录所在链段，统计与结论正确")
    void verifyByTimeRange() {
        record("alice", "ACTION_0");
        Instant from = Instant.now();
        record("alice", "ACTION_1");
        record("alice", "ACTION_2");
        Instant to = Instant.now();
        record("alice", "ACTION_3");

        IntegrityReport report = verifyService.verify(from, to, null, null);

        assertThat(report.intact()).as(report.anomalyMessage()).isTrue();
        assertThat(report.fromChainIndex()).isEqualTo(1);
        assertThat(report.toChainIndex()).isEqualTo(2);
        assertThat(report.chainedCount()).isEqualTo(2);
    }

    /** 构造一条 31 天前的未入链记录（由 chainService 入链）。 */
    private AuditEvent oldEvent(String eventId) {
        return new AuditEvent(eventId, "req-" + eventId, 1, "alice", "ORDER_CREATE",
                "ORDER", "ORD-OLD", Map.of(), OperationResult.SUCCESS, null,
                Instant.now().minus(31, ChronoUnit.DAYS), 0, false);
    }
}

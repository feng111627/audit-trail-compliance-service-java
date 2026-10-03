package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.feng111627.audittrailcomplianceservicejava.audit.config.AuditProperties;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.AuditEventHash;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.ChainEntry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.HashChainService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryAnonymizationRegistry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryChainEntryRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport.AnomalyType;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityVerificationService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.DefaultMaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.InMemoryAuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.DefaultAuditService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 业务点：防篡改哈希链与完整性校验。
 * 新记录与已落库记录建立可验证的先后关联；事后改库能检出并定位到第一条；
 * 历史遗留、正常清理（删除/匿名化）不误报；并发与重试下关联不乱、不重复、不断链。
 */
@DisplayName("业务点-防篡改哈希链与完整性校验")
class TamperEvidenceTest {

    private InMemoryAuditEventRepository eventRepo;
    private InMemoryChainEntryRepository chainRepo;
    private InMemoryAnonymizationRegistry anonymizationRegistry;
    private HashChainService chainService;
    private IntegrityVerificationService verificationService;
    private AuditProperties properties;

    @BeforeEach
    void setUp() {
        eventRepo = new InMemoryAuditEventRepository();
        chainRepo = new InMemoryChainEntryRepository();
        anonymizationRegistry = new InMemoryAnonymizationRegistry();
        chainService = new HashChainService(chainRepo);
        verificationService = new IntegrityVerificationService(chainRepo, eventRepo, anonymizationRegistry);
        properties = new AuditProperties();
    }

    private DefaultAuditService auditService() {
        return new DefaultAuditService(eventRepo, new DefaultMaskingService(),
                new AuditAccessControl(), properties, chainService, anonymizationRegistry);
    }

    private AuditEvent recordOne(DefaultAuditService service, String actor, String action) {
        return service.record(actor, action, "ORDER", "ORD-1",
                Map.of("product", "book"), OperationResult.SUCCESS, null);
    }

    @Test
    @DisplayName("新记录自动入链：校验通过，覆盖量与链上环节数一致")
    void newRecordsAreChainedAndVerify() {
        DefaultAuditService service = auditService();
        recordOne(service, "alice", "ORDER_CREATE");
        recordOne(service, "alice", "ORDER_QUERY");
        recordOne(service, "bob", "ORDER_CANCEL");

        assertThat(chainRepo.count()).isEqualTo(3);
        ChainEntry first = chainRepo.findByPosition(1).orElseThrow();
        assertThat(first.previousHash()).isEqualTo(AuditEventHash.GENESIS);

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.firstAnomaly()).isNull();
        assertThat(report.verifiedCount()).isEqualTo(3);
        assertThat(report.checkedPositions()).isEqualTo(3);
        assertThat(report.legacyCount()).isZero();
        assertThat(report.purgedCount()).isZero();
    }

    @Test
    @DisplayName("绕过接口直接改库：检出篡改并定位到第一条对不上的记录")
    void tamperedRecordIsDetectedAndLocated() {
        DefaultAuditService service = auditService();
        recordOne(service, "alice", "ORDER_CREATE");
        AuditEvent victim = recordOne(service, "alice", "ORDER_UPDATE_PHONE");
        recordOne(service, "bob", "ORDER_CANCEL");

        // 模拟绕过接口直接改库：把第二条的结果从 SUCCESS 改成 FAILED
        AuditEvent tampered = new AuditEvent(victim.eventId(), victim.requestId(), victim.sequence(),
                victim.actor(), victim.action(), victim.resourceType(), victim.resourceId(),
                victim.parameters(), OperationResult.FAILED, "事后被人改动",
                victim.timestamp(), victim.durationMillis(), victim.async());
        eventRepo.forceReplace(tampered);

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isFalse();
        assertThat(report.firstAnomaly()).isNotNull();
        // 精确定位：从被改的那一条开始对不上
        assertThat(report.firstAnomaly().position()).isEqualTo(2);
        assertThat(report.firstAnomaly().eventId()).isEqualTo(victim.eventId());
        assertThat(report.firstAnomaly().type()).isEqualTo(AnomalyType.HASH_MISMATCH);
        // 未被动过的另外两条仍然校验通过
        assertThat(report.verifiedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("历史遗留记录（未入链）单独计数，不被误报为篡改")
    void legacyRecordsAreNotReportedAsTampered() {
        DefaultAuditService service = auditService();
        recordOne(service, "alice", "ORDER_CREATE");

        // 模拟能力上线前就已存在的历史记录：直接落库、没有链上环节
        AuditEvent legacy = new AuditEvent("evt-legacy-1", "req-legacy", 1, "carol",
                "ORDER_CREATE", "ORDER", "ORD-OLD", Map.of(), OperationResult.SUCCESS,
                null, Instant.now(), 0, false);
        eventRepo.saveIfAbsent(legacy);

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.legacyCount()).isEqualTo(1);
        assertThat(report.verifiedCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("留存策略物理删除的记录：计入 purgedCount，不误报为篡改")
    void purgedRecordsAreNotReportedAsTampered() {
        properties.getRetention().setPurgeMode("DELETE");
        properties.getRetention().setDays(0); // 立即过期，模拟留存清理
        DefaultAuditService service = auditService();
        recordOne(service, "alice", "ORDER_CREATE");
        recordOne(service, "alice", "ORDER_QUERY");

        long purged = service.purgeExpired();
        assertThat(purged).isEqualTo(2);
        assertThat(eventRepo.countAll()).isZero();

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.purgedCount()).isEqualTo(2);
        assertThat(report.firstAnomaly()).isNull();
    }

    @Test
    @DisplayName("留存策略匿名化的记录：凭登记哈希通过校验，不误报为篡改")
    void anonymizedRecordsAreNotReportedAsTampered() {
        properties.getRetention().setPurgeMode("ANONYMIZE");
        properties.getRetention().setDays(0);
        DefaultAuditService service = auditService();
        AuditEvent event = recordOne(service, "alice", "ORDER_CREATE");
        recordOne(service, "alice", "ORDER_QUERY");

        long anonymized = service.purgeExpired();
        assertThat(anonymized).isEqualTo(2);
        assertThat(eventRepo.findByEventId(event.eventId()).orElseThrow().actor())
                .isEqualTo("deleted@retention");

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.anonymizedCount()).isEqualTo(2);
        assertThat(report.verifiedCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("匿名化登记之外的改动仍会被检出（匿名化不是篡改的挡箭牌）")
    void tamperingAfterAnonymizationIsStillDetected() {
        properties.getRetention().setPurgeMode("ANONYMIZE");
        properties.getRetention().setDays(0);
        DefaultAuditService service = auditService();
        AuditEvent event = recordOne(service, "alice", "ORDER_CREATE");
        service.purgeExpired();

        // 匿名化之后又被改了一手（比如改了 action）
        AuditEvent current = eventRepo.findByEventId(event.eventId()).orElseThrow();
        eventRepo.forceReplace(new AuditEvent(current.eventId(), current.requestId(),
                current.sequence(), current.actor(), "ORDER_DELETE", current.resourceType(),
                current.resourceId(), current.parameters(), current.result(), current.reason(),
                current.timestamp(), current.durationMillis(), current.async()));

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isFalse();
        assertThat(report.firstAnomaly().eventId()).isEqualTo(event.eventId());
        assertThat(report.firstAnomaly().type()).isEqualTo(AnomalyType.HASH_MISMATCH);
    }

    @Test
    @DisplayName("链上环节的先后关联被断开：检出断链并定位到断开处")
    void brokenChainLinkIsDetected() {
        // 手工构造一条第二环 previousHash 对不上的链（模拟环节被替换）
        AuditEvent eventA = new AuditEvent("evt-a", "req-a", 1, "alice", "A",
                "ORDER", "ORD-1", Map.of(), OperationResult.SUCCESS, null, Instant.now(), 0, false);
        AuditEvent eventB = new AuditEvent("evt-b", "req-b", 1, "bob", "B",
                "ORDER", "ORD-2", Map.of(), OperationResult.SUCCESS, null, Instant.now(), 0, false);
        eventRepo.saveIfAbsent(eventA);
        eventRepo.saveIfAbsent(eventB);
        chainRepo.saveIfAbsent(new ChainEntry(1, "evt-a", eventA.timestamp(),
                AuditEventHash.GENESIS, AuditEventHash.compute(eventA, AuditEventHash.GENESIS)));
        String wrongPrevious = "f".repeat(64);
        chainRepo.saveIfAbsent(new ChainEntry(2, "evt-b", eventB.timestamp(),
                wrongPrevious, AuditEventHash.compute(eventB, wrongPrevious)));

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isFalse();
        assertThat(report.firstAnomaly().position()).isEqualTo(2);
        assertThat(report.firstAnomaly().type()).isEqualTo(AnomalyType.CHAIN_LINK_BROKEN);
    }

    @Test
    @DisplayName("多线程并发写入：链上位置连续无重复，关联不乱、校验通过")
    void concurrentWritesKeepChainConsistent() throws Exception {
        DefaultAuditService service = auditService();
        int threads = 8;
        int perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int idx = t;
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                for (int i = 0; i < perThread; i++) {
                    service.record("actor-" + idx, "ACTION-" + i, "ORDER", "ORD-" + idx,
                            Map.of("i", i), OperationResult.SUCCESS, null);
                }
                return null;
            }));
        }
        assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
        go.countDown();
        for (Future<?> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        int total = threads * perThread;
        assertThat(chainRepo.count()).isEqualTo(total);
        // position 恰好是 1..N，连续、无重复、无空洞
        List<Long> positions = chainRepo.findRange(1, total).stream()
                .map(ChainEntry::position).sorted().toList();
        assertThat(positions).hasSize(total);
        for (int i = 0; i < total; i++) {
            assertThat(positions.get(i)).isEqualTo(i + 1L);
        }

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.verifiedCount()).isEqualTo(total);
    }

    @Test
    @DisplayName("同一请求标识重试/并发重复入链：只入链一次，不产生重复环节点")
    void retryDoesNotDuplicateChainEntries() throws Exception {
        DefaultAuditService service = auditService();
        AuditEvent event = recordOne(service, "alice", "ORDER_CREATE");
        assertThat(chainRepo.count()).isEqualTo(1);

        // 模拟调用方拿同一请求标识重试：同一 eventId 并发重复入链
        int attempts = 16;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        List<Future<ChainEntry>> futures = new ArrayList<>();
        for (int i = 0; i < attempts; i++) {
            futures.add(pool.submit(() -> chainService.appendIfNew(event)));
        }
        List<ChainEntry> results = new ArrayList<>();
        for (Future<ChainEntry> future : futures) {
            results.add(future.get(10, TimeUnit.SECONDS));
        }
        pool.shutdown();

        assertThat(chainRepo.count()).isEqualTo(1);
        assertThat(results).allSatisfy(e -> {
            assertThat(e.position()).isEqualTo(1);
            assertThat(e.eventId()).isEqualTo(event.eventId());
        });

        IntegrityReport report = verificationService.verify(null, null);
        assertThat(report.intact()).isTrue();
        assertThat(report.checkedPositions()).isEqualTo(1);
    }

    @Test
    @DisplayName("按时间范围校验：只覆盖范围内的记录，范围外的篡改不影响本次结论")
    void verifyByTimeRange() {
        DefaultAuditService service = auditService();
        AuditEvent first = recordOne(service, "alice", "ORDER_CREATE");
        AuditEvent second = recordOne(service, "alice", "ORDER_QUERY");

        // 只校验第二条之后到现在的范围：覆盖 1 条
        IntegrityReport report = verificationService.verify(second.timestamp(), null);
        assertThat(report.intact()).isTrue();
        assertThat(report.checkedPositions()).isEqualTo(1);
        assertThat(report.verifiedCount()).isEqualTo(1);

        // 只校验第一条：也各自独立通过
        IntegrityReport firstOnly = verificationService.verify(null, second.timestamp().minusNanos(1));
        assertThat(firstOnly.intact()).isTrue();
        assertThat(firstOnly.checkedPositions()).isEqualTo(1);
        assertThat(firstOnly.verifiedCount()).isEqualTo(1);
        assertThat(first.eventId()).isNotEqualTo(second.eventId());
    }
}

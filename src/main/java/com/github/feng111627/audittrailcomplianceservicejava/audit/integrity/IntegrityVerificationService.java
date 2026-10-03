package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.HashService;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * 完整性校验：按时间范围或链上序号范围，对哈希链做一次流式校验。
 *
 * <p>实现要点：
 * <ul>
 *   <li>分批（每批 {@value #BATCH_SIZE} 条）从仓储按链序取记录，内存中只持有一批，
 *       数据量大也不会一次性把全量拉进内存；</li>
 *   <li>只读仓储快照做逐条重算与比对，不加写锁、不阻塞正常留痕写入；</li>
 *   <li>历史遗留记录（无链字段）只统计为 legacyCount，不算异常；</li>
 *   <li>命中正常清理墓碑的链上缺口计为 purgedCount，不算异常；</li>
 *   <li>发现异常时记录“第一处”异常的类型、链上序号与 eventId，继续扫完以给出完整统计。</li>
 * </ul>
 */
@Service
public class IntegrityVerificationService {

    /** 每批加载的链上记录数。 */
    static final int BATCH_SIZE = 200;

    private final AuditEventRepository repository;
    private final PurgeTombstoneStore tombstoneStore;
    private final HashService hashService;
    private final HashChainService hashChainService;

    public IntegrityVerificationService(AuditEventRepository repository,
                                        PurgeTombstoneStore tombstoneStore,
                                        HashService hashService,
                                        HashChainService hashChainService) {
        this.repository = repository;
        this.tombstoneStore = tombstoneStore;
        this.hashService = hashService;
        this.hashChainService = hashChainService;
    }

    /**
     * 跑一次完整性校验。
     *
     * @param from      时间范围起点（含），null 不限
     * @param to        时间范围终点（含），null 不限
     * @param fromIndex 链上序号起点（含），优先于 from；null 则按时间/从头
     * @param toIndex   链上序号终点（含），优先于 to；null 则按时间/到链尾
     */
    public IntegrityReport verify(Instant from, Instant to, Long fromIndex, Long toIndex) {
        long legacyCount = repository.countLegacy(from, to);

        Long start = resolveStart(from, fromIndex);
        Long end = resolveEnd(to, toIndex);
        if (start == null || end == null || start > end) {
            // 范围内没有入链记录：只有历史遗留统计，无异常
            return IntegrityReport.clean(0, 0, legacyCount, 0, 0, start, end);
        }

        FirstAnomaly anomaly = new FirstAnomaly();

        // 定位链段起点的前序哈希：前一条入链记录 -> 正常清理墓碑 -> 都没有则是被人为删除
        String expectedHash;
        if (start == 0) {
            expectedHash = AuditEvent.GENESIS;
        } else {
            expectedHash = repository.findByChainIndex(start - 1)
                    .map(AuditEvent::eventHash)
                    .or(() -> tombstoneStore.findHash(start - 1))
                    .orElse(null);
            if (expectedHash == null) {
                anomaly.record(AnomalyType.RECORD_MISSING, start - 1, null,
                        "链上序号 " + (start - 1) + " 的记录缺失，且没有正常清理的墓碑记录");
            }
        }

        long scanned = 0;
        long purged = 0;
        long anonymized = 0;
        long cursor = start;

        while (cursor <= end) {
            List<AuditEvent> batch = repository.findChainedFrom(cursor, BATCH_SIZE);
            if (batch.isEmpty()) {
                // 链段剩余部分整体缺失：逐序号核对墓碑
                for (long missing = cursor; missing <= end; missing++) {
                    var tombstone = tombstoneStore.findHash(missing);
                    if (tombstone.isPresent()) {
                        purged++;
                        expectedHash = tombstone.get();
                    } else {
                        anomaly.record(AnomalyType.RECORD_MISSING, missing, null,
                                "链上序号 " + missing + " 的记录缺失，且没有正常清理的墓碑记录");
                        expectedHash = null;
                    }
                }
                break;
            }
            boolean beyondEnd = false;
            for (AuditEvent event : batch) {
                if (event.chainIndex() > end) {
                    beyondEnd = true;
                    break;
                }
                // 序号缺口：逐序号核对墓碑，区分“正常清理”与“被人为删除”
                for (long missing = cursor; missing < event.chainIndex(); missing++) {
                    var tombstone = tombstoneStore.findHash(missing);
                    if (tombstone.isPresent()) {
                        purged++;
                        expectedHash = tombstone.get();
                    } else {
                        anomaly.record(AnomalyType.RECORD_MISSING, missing, null,
                                "链上序号 " + missing + " 的记录缺失，且没有正常清理的墓碑记录");
                        expectedHash = null;
                    }
                }
                // 链关联校验：previousHash 必须等于前序记录（或墓碑）的哈希
                if (expectedHash != null && !expectedHash.equals(event.previousHash())) {
                    anomaly.record(AnomalyType.CHAIN_LINK_BROKEN, event.chainIndex(), event.eventId(),
                            "记录 " + event.eventId() + "（链上序号 " + event.chainIndex()
                                    + "）的 previousHash 与前序记录对不上，链在此处断开");
                }
                // 内容校验：按当前内容重算，与落库时的哈希比对（匿名化记录比对匿名化哈希）
                String storedHash = event.anonymizedHash() != null ? event.anonymizedHash() : event.eventHash();
                String recomputed = hashService.contentHash(event, event.previousHash());
                if (!recomputed.equals(storedHash)) {
                    anomaly.record(AnomalyType.CONTENT_TAMPERED, event.chainIndex(), event.eventId(),
                            "记录 " + event.eventId() + "（链上序号 " + event.chainIndex()
                                    + "）的内容与落库时的哈希对不上，内容疑似被改动");
                }
                // 匿名化合法性：带匿名化哈希的记录必须确实被匿名化（防止借匿名化掩盖篡改）
                if (event.anonymizedHash() != null) {
                    anonymized++;
                    if (!"deleted@retention".equals(event.actor()) || !event.parameters().isEmpty()) {
                        anomaly.record(AnomalyType.ANONYMIZATION_INVALID, event.chainIndex(), event.eventId(),
                                "记录 " + event.eventId() + "（链上序号 " + event.chainIndex()
                                        + "）带有匿名化哈希，但内容并不像正常匿名化产物");
                    }
                }
                scanned++;
                expectedHash = event.eventHash();
                cursor = event.chainIndex() + 1;
            }
            if (beyondEnd) {
                break;
            }
        }

        // 截断校验：校验到链尾时，仓储里的链尾不应短于写入侧已推进到的链尾
        if (toIndex == null && to == null) {
            long knownTail = hashChainService.currentTailIndex();
            if (knownTail > end) {
                anomaly.record(AnomalyType.RECORD_MISSING, end + 1, null,
                        "链尾记录缺失：写入侧已推进到序号 " + knownTail + "，但仓储中最新入链记录只到序号 " + end
                                + "，链尾疑似被人为截断");
            }
        }

        if (anomaly.type != null) {
            return new IntegrityReport(false, scanned, scanned, legacyCount, purged, anonymized,
                    start, end, anomaly.type, anomaly.chainIndex, anomaly.eventId, anomaly.message);
        }
        return IntegrityReport.clean(scanned, scanned, legacyCount, purged, anonymized, start, end);
    }

    private Long resolveStart(Instant from, Long fromIndex) {
        if (fromIndex != null) {
            return fromIndex;
        }
        if (from != null) {
            return repository.findFirstChainedAtOrAfter(from)
                    .map(AuditEvent::chainIndex)
                    .orElse(null);
        }
        return 0L;
    }

    private Long resolveEnd(Instant to, Long toIndex) {
        if (toIndex != null) {
            return toIndex;
        }
        if (to != null) {
            return repository.findLastChainedAtOrBefore(to)
                    .map(AuditEvent::chainIndex)
                    .orElse(null);
        }
        return repository.findLatestChained()
                .map(AuditEvent::chainIndex)
                .orElse(null);
    }

    /** 只记第一处异常，后续异常不覆盖（统计仍继续）。 */
    private static final class FirstAnomaly {
        private AnomalyType type;
        private Long chainIndex;
        private String eventId;
        private String message;

        void record(AnomalyType type, long chainIndex, String eventId, String message) {
            if (this.type == null) {
                this.type = type;
                this.chainIndex = chainIndex;
                this.eventId = eventId;
                this.message = message;
            }
        }
    }
}

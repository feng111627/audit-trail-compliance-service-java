package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport.AnomalyType;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport.FirstAnomaly;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * 完整性校验：对哈希链做一次可验证的重放，支持按时间范围或按链上位置区间。
 *
 * <p>对范围内每个链上环节做两类检查：
 * <ol>
 *   <li>链衔接：本环 previousHash 必须等于前一环的 entryHash（首环为 GENESIS），
 *       否则说明链上环节被删除/替换/重排；</li>
 *   <li>内容一致：用库里当前记录内容重算哈希，必须等于链上登记值，
 *       否则说明记录事后被改动。</li>
 * </ol>
 *
 * <p>记录已不在库里时按登记情况区分：
 * <ul>
 *   <li>已在 {@link PurgeRegistry} 登记 → 留存策略正常清理，计入 purgedCount；</li>
 *   <li>未登记 → 人为整条删除/被换成别的记录，报 RECORD_MISSING 并定位到该环。</li>
 * </ul>
 *
 * <p>不算异常的两类情况，单独计数上报：
 * <ul>
 *   <li>历史遗留：记录存在但没有链上环节（能力上线前已落库），计入 legacyCount；</li>
 *   <li>正常清理：上述已登记的物理删除（purgedCount），
 *       或记录被正常匿名化且与匿名化登记哈希一致（anonymizedCount）。</li>
 * </ul>
 *
 * <p>实现上分批流式读取（每批 {@value #BATCH_SIZE} 条），不把全量记录拉进内存；
 * 只读仓储快照、不持有写入锁，不会阻塞正常留痕写入。
 */
@Service
public class IntegrityVerificationService {

    static final int BATCH_SIZE = 500;

    private final ChainEntryRepository chainRepository;
    private final AuditEventRepository eventRepository;
    private final AnonymizationRegistry anonymizationRegistry;
    private final PurgeRegistry purgeRegistry;

    public IntegrityVerificationService(ChainEntryRepository chainRepository,
                                        AuditEventRepository eventRepository,
                                        AnonymizationRegistry anonymizationRegistry,
                                        PurgeRegistry purgeRegistry) {
        this.chainRepository = chainRepository;
        this.eventRepository = eventRepository;
        this.anonymizationRegistry = anonymizationRegistry;
        this.purgeRegistry = purgeRegistry;
    }

    /**
     * 校验落库时间在 [from, to]（闭区间，null 表示不限）的记录。
     * 返回整体是否完整、覆盖量，以及第一处异常的位置。
     */
    public IntegrityReport verify(Instant from, Instant to) {
        Instant effectiveFrom = from == null ? Instant.EPOCH : from;
        Instant effectiveTo = to == null ? Instant.MAX : to;

        Counters counters = new Counters();
        ChainEntry previousEntry = null;
        long offset = 0;
        while (true) {
            List<ChainEntry> batch = chainRepository.findByEventTimestampBetween(
                    effectiveFrom, effectiveTo, offset, BATCH_SIZE);
            if (batch.isEmpty()) {
                break;
            }
            offset += batch.size();
            for (ChainEntry entry : batch) {
                previousEntry = checkEntry(entry, previousEntry, counters);
            }
            if (batch.size() < BATCH_SIZE) {
                break;
            }
        }

        // 历史遗留：范围内有记录但尚未入链的，单独计数，不算篡改
        counters.legacy = countLegacy(effectiveFrom, effectiveTo);
        return counters.toReport();
    }

    /**
     * 校验链上位置在 [fromPosition, toPosition]（闭区间，toPosition 为 null 表示到链尾）的环节。
     * 衔接校验会回查区间外的前驱环，因此区间起点本身的断链也能检出。
     */
    public IntegrityReport verifyRange(long fromPosition, Long toPosition) {
        if (fromPosition < 1) {
            throw new IllegalArgumentException("fromPosition 必须 >= 1: " + fromPosition);
        }
        if (toPosition != null && toPosition < fromPosition) {
            throw new IllegalArgumentException(
                    "toPosition 必须 >= fromPosition: " + toPosition + " < " + fromPosition);
        }

        Counters counters = new Counters();
        ChainEntry previousEntry = null;
        long next = fromPosition;
        while (toPosition == null || next <= toPosition) {
            int limit = toPosition == null
                    ? BATCH_SIZE
                    : (int) Math.min(BATCH_SIZE, toPosition - next + 1);
            List<ChainEntry> batch = chainRepository.findRange(next, limit);
            if (batch.isEmpty()) {
                break;
            }
            for (ChainEntry entry : batch) {
                previousEntry = checkEntry(entry, previousEntry, counters);
            }
            next = batch.get(batch.size() - 1).position() + 1;
            if (batch.size() < limit) {
                break;
            }
        }
        return counters.toReport();
    }

    /** 校验单个环节：链衔接 + 内容一致/正常清理区分。返回供下一环复用的前驱。 */
    private ChainEntry checkEntry(ChainEntry entry, ChainEntry previousEntry, Counters counters) {
        counters.checked++;
        ChainEntry predecessor = predecessorOf(entry, previousEntry);
        FirstAnomaly linkAnomaly = checkLinkage(entry, predecessor);
        if (linkAnomaly != null && counters.firstAnomaly == null) {
            counters.firstAnomaly = linkAnomaly;
        }

        Optional<AuditEvent> event = eventRepository.findByEventId(entry.eventId());
        if (event.isEmpty()) {
            if (purgeRegistry.isPurged(entry.eventId())) {
                // 留存策略正常物理删除，已登记，不算篡改。
                counters.purged++;
            } else if (counters.firstAnomaly == null) {
                // 未登记而记录缺失：人为整条删除，或整条被换成别的记录。
                counters.firstAnomaly = new FirstAnomaly(entry.position(), entry.eventId(),
                        AnomalyType.RECORD_MISSING,
                        "已入链记录在库里查不到，且未登记为留存策略清理，疑似被人为整条删除或替换");
            }
        } else {
            String recomputed = AuditEventHash.compute(event.get(), entry.previousHash());
            if (recomputed.equals(entry.entryHash())) {
                counters.verified++;
            } else if (isProperlyAnonymized(entry, recomputed)) {
                counters.verified++;
                counters.anonymized++;
            } else if (counters.firstAnomaly == null) {
                counters.firstAnomaly = new FirstAnomaly(entry.position(), entry.eventId(),
                        AnomalyType.HASH_MISMATCH,
                        "记录内容与链上登记哈希不一致，疑似落库后被改动");
            }
        }
        return entry;
    }

    /** 取本环的前驱：扫描顺序相邻时直接复用上一环，否则按 position 回查（范围内可能有空洞）。 */
    private ChainEntry predecessorOf(ChainEntry entry, ChainEntry previousEntry) {
        if (entry.position() == 1) {
            return null;
        }
        if (previousEntry != null && previousEntry.position() == entry.position() - 1) {
            return previousEntry;
        }
        return chainRepository.findByPosition(entry.position() - 1).orElse(null);
    }

    private FirstAnomaly checkLinkage(ChainEntry entry, ChainEntry predecessor) {
        String expectedPrevious = entry.position() == 1
                ? AuditEventHash.GENESIS
                : predecessor == null ? null : predecessor.entryHash();
        if (expectedPrevious == null) {
            return new FirstAnomaly(entry.position(), entry.eventId(),
                    AnomalyType.CHAIN_LINK_BROKEN,
                    "链上前一环节（position=" + (entry.position() - 1) + "）缺失，疑似环节被删除");
        }
        if (!expectedPrevious.equals(entry.previousHash())) {
            return new FirstAnomaly(entry.position(), entry.eventId(),
                    AnomalyType.CHAIN_LINK_BROKEN,
                    "本环 previousHash 与前一环 entryHash 不一致，链在此处断开");
        }
        return null;
    }

    /** 记录被正常匿名化：重算哈希与匿名化登记值一致，属于留存策略行为而非篡改。 */
    private boolean isProperlyAnonymized(ChainEntry entry, String recomputedHash) {
        return anonymizationRegistry.findAnonymizedHash(entry.eventId())
                .map(recomputedHash::equals)
                .orElse(false);
    }

    /** 范围内存在但没有链上环节的记录数（能力上线前的历史遗留）。 */
    private long countLegacy(Instant from, Instant to) {
        long legacy = 0;
        long offset = 0;
        while (true) {
            List<AuditEvent> batch = eventRepository.findByTimestampBetween(from, to, offset, BATCH_SIZE);
            if (batch.isEmpty()) {
                break;
            }
            offset += batch.size();
            for (AuditEvent event : batch) {
                if (chainRepository.findByEventId(event.eventId()).isEmpty()) {
                    legacy++;
                }
            }
            if (batch.size() < BATCH_SIZE) {
                break;
            }
        }
        return legacy;
    }

    /** 一次校验的累计计数器。 */
    private static final class Counters {
        private long verified;
        private long anonymized;
        private long purged;
        private long legacy;
        private long checked;
        private FirstAnomaly firstAnomaly;

        private IntegrityReport toReport() {
            return new IntegrityReport(firstAnomaly == null, verified, anonymized,
                    purged, legacy, checked, firstAnomaly);
        }
    }
}

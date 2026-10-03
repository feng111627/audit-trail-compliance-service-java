package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport.AnomalyType;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport.FirstAnomaly;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * 完整性校验：按时间范围对哈希链做一次可验证的重放。
 *
 * <p>对范围内每个链上环节做两类检查：
 * <ol>
 *   <li>链衔接：本环 previousHash 必须等于前一环的 entryHash（首环为 GENESIS），
 *       否则说明链上环节被删除/替换/重排；</li>
 *   <li>内容一致：用库里当前记录内容重算哈希，必须等于链上登记值，
 *       否则说明记录事后被改动。</li>
 * </ol>
 *
 * <p>不算异常的两类情况，单独计数上报：
 * <ul>
 *   <li>历史遗留：记录存在但没有链上环节（能力上线前已落库），计入 legacyCount；</li>
 *   <li>正常清理：链上环节在、记录已被留存策略物理删除（purgedCount），
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

    public IntegrityVerificationService(ChainEntryRepository chainRepository,
                                        AuditEventRepository eventRepository,
                                        AnonymizationRegistry anonymizationRegistry) {
        this.chainRepository = chainRepository;
        this.eventRepository = eventRepository;
        this.anonymizationRegistry = anonymizationRegistry;
    }

    /**
     * 校验落库时间在 [from, to]（闭区间，null 表示不限）的记录。
     * 返回整体是否完整、覆盖量，以及第一处异常的位置。
     */
    public IntegrityReport verify(Instant from, Instant to) {
        Instant effectiveFrom = from == null ? Instant.EPOCH : from;
        Instant effectiveTo = to == null ? Instant.MAX : to;

        long verified = 0;
        long anonymized = 0;
        long purged = 0;
        long checked = 0;
        FirstAnomaly firstAnomaly = null;

        // —— 链上环节：分批扫描，逐环做衔接与内容校验 ——
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
                checked++;
                ChainEntry predecessor = predecessorOf(entry, previousEntry);
                FirstAnomaly linkAnomaly = checkLinkage(entry, predecessor);
                if (linkAnomaly != null && firstAnomaly == null) {
                    firstAnomaly = linkAnomaly;
                }

                Optional<AuditEvent> event = eventRepository.findByEventId(entry.eventId());
                if (event.isEmpty()) {
                    // 记录已不在：留存策略物理删除属于正常清理，不算篡改。
                    purged++;
                } else {
                    String recomputed = AuditEventHash.compute(event.get(), entry.previousHash());
                    if (recomputed.equals(entry.entryHash())) {
                        verified++;
                    } else if (isProperlyAnonymized(entry, recomputed)) {
                        verified++;
                        anonymized++;
                    } else if (firstAnomaly == null) {
                        firstAnomaly = new FirstAnomaly(entry.position(), entry.eventId(),
                                AnomalyType.HASH_MISMATCH,
                                "记录内容与链上登记哈希不一致，疑似落库后被改动");
                    }
                }
                previousEntry = entry;
            }
            if (batch.size() < BATCH_SIZE) {
                break;
            }
        }

        // —— 历史遗留：范围内有记录但尚未入链的，单独计数，不算篡改 ——
        long legacy = countLegacy(effectiveFrom, effectiveTo);

        return new IntegrityReport(firstAnomaly == null, verified, anonymized,
                purged, legacy, checked, firstAnomaly);
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
}

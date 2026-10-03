package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

/**
 * 哈希链写入：每条新落库的审计记录追加为链上一环。
 *
 * <p>并发与重试语义：
 * <ul>
 *   <li>position 分配与 previousHash 读取在一个短临界区内完成（仅哈希计算量级），
 *       多线程并发写入不会断链、不会乱序；</li>
 *   <li>同一 eventId 只入链一次（仓储幂等兜底），调用方拿同一请求标识重试
 *       不会产生重复环节点；</li>
 *   <li>校验方只读仓储快照、不碰这把锁，校验不会在写入关键路径上阻塞写。</li>
 * </ul>
 */
@Service
public class HashChainService {

    private final ChainEntryRepository chainRepository;
    /** 仅保护“读链尾 + 分配 position + 落链”这一小段，持锁时间极短。 */
    private final ReentrantLock appendLock = new ReentrantLock();

    public HashChainService(ChainEntryRepository chainRepository) {
        this.chainRepository = chainRepository;
    }

    /**
     * 把一条已落库的审计记录追加到链上；同一 eventId 重复调用直接返回已存在的环。
     */
    public ChainEntry appendIfNew(AuditEvent event) {
        Optional<ChainEntry> existing = chainRepository.findByEventId(event.eventId());
        if (existing.isPresent()) {
            return existing.get();
        }
        appendLock.lock();
        try {
            // 锁内复查：并发下另一线程可能已把同一 eventId 入链。
            existing = chainRepository.findByEventId(event.eventId());
            if (existing.isPresent()) {
                return existing.get();
            }
            ChainEntry latest = chainRepository.findLatest().orElse(null);
            long position = latest == null ? 1 : latest.position() + 1;
            String previousHash = latest == null ? AuditEventHash.GENESIS : latest.entryHash();
            ChainEntry entry = new ChainEntry(position, event.eventId(), event.timestamp(),
                    previousHash, AuditEventHash.compute(event, previousHash));
            chainRepository.saveIfAbsent(entry);
            return entry;
        } finally {
            appendLock.unlock();
        }
    }

    /** 当前链尾，空链返回 empty。 */
    public Optional<ChainEntry> latest() {
        return chainRepository.findLatest();
    }

    /**
     * 某条已入链记录在链上的前驱哈希（匿名化登记时用作重算锚点）；
     * 未入链（历史遗留）返回 empty。
     */
    public Optional<String> latestAnonymizedAnchor(String eventId) {
        return chainRepository.findByEventId(eventId).map(ChainEntry::previousHash);
    }
}

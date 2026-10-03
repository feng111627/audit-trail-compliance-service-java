package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.HashService;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

/**
 * 防篡改哈希链写入器：每条新记录带上前一条记录的哈希（previousHash）与
 * 自己的内容哈希（eventHash）后落库，形成可验证的先后关联。
 *
 * <p>并发与重试语义：
 * <ul>
 *   <li>链尾推进在短锁内完成，锁内只做“算哈希 + 幂等落库”，不做任何慢 IO，
 *       不会长时间阻塞正常写入；</li>
 *   <li>落库走仓储 saveIfAbsent：同一 eventId 的重试不会重复落库，
 *       也不会推进链尾，链不会出现重复记录或断链；</li>
 *   <li>启动时从仓储恢复链尾，重启后新记录接在已有链尾之后。</li>
 * </ul>
 */
@Service
public class HashChainService {

    private final AuditEventRepository repository;
    private final HashService hashService;
    private final ReentrantLock chainLock = new ReentrantLock();

    /** 链尾序号与哈希（仅持内存指针，记录本体在仓储）。 */
    private long tailIndex = AuditEvent.LEGACY_CHAIN_INDEX;
    private String tailHash = AuditEvent.GENESIS;

    public HashChainService(AuditEventRepository repository, HashService hashService) {
        this.repository = repository;
        this.hashService = hashService;
        repository.findLatestChained().ifPresent(tail -> {
            this.tailIndex = tail.chainIndex();
            this.tailHash = tail.eventHash();
        });
    }

    /**
     * 把一条记录接入链尾并落库。
     *
     * @return 实际生效的入链记录；若同一 eventId 已存在（重试），返回库中已有记录，
     *         链状态不变。
     */
    public AuditEvent append(AuditEvent event) {
        chainLock.lock();
        try {
            long chainIndex = tailIndex + 1;
            String previousHash = tailHash;
            String eventHash = hashService.chainHash(event, previousHash);
            AuditEvent chained = new AuditEvent(
                    event.eventId(), event.requestId(), event.sequence(),
                    event.actor(), event.action(), event.resourceType(), event.resourceId(),
                    event.parameters(), event.result(), event.reason(),
                    event.timestamp(), event.durationMillis(), event.async(),
                    chainIndex, previousHash, eventHash, null);

            if (!repository.saveIfAbsent(chained)) {
                // 重试/并发下同一 eventId 已落库：不推进链尾，直接返回已有记录
                return repository.findByEventId(event.eventId()).orElse(chained);
            }
            tailIndex = chainIndex;
            tailHash = eventHash;
            return chained;
        } finally {
            chainLock.unlock();
        }
    }

    /** 当前链尾序号（无入链记录时为 -1），主要供测试与诊断。 */
    public long currentTailIndex() {
        chainLock.lock();
        try {
            return tailIndex;
        } finally {
            chainLock.unlock();
        }
    }
}

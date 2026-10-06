package com.github.feng111627.audittrailcomplianceservicejava.audit.service;

import com.github.feng111627.audittrailcomplianceservicejava.audit.config.AuditProperties;
import com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.AnonymizationRegistry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.AuditEventHash;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.HashChainService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryAnonymizationRegistry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryChainEntryRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.InMemoryPurgeRegistry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.PurgeRegistry;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.MaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditPage;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 默认留痕服务。
 *
 * <p>eventId 由 requestId + 请求内序列号确定性生成，同一次操作即使切面/调用方重试，
 * 也只会落库一次（仓储 saveIfAbsent 兜底）；不同请求的 requestId 不同，天然不串。
 */
@Service
public class DefaultAuditService implements AuditService {

    private final AuditEventRepository repository;
    private final MaskingService maskingService;
    private final AuditAccessControl accessControl;
    private final AuditProperties properties;
    private final HashChainService hashChainService;
    private final AnonymizationRegistry anonymizationRegistry;
    private final PurgeRegistry purgeRegistry;

    @Autowired
    public DefaultAuditService(AuditEventRepository repository,
                               MaskingService maskingService,
                               AuditAccessControl accessControl,
                               AuditProperties properties,
                               HashChainService hashChainService,
                               AnonymizationRegistry anonymizationRegistry,
                               PurgeRegistry purgeRegistry) {
        this.repository = repository;
        this.maskingService = maskingService;
        this.accessControl = accessControl;
        this.properties = properties;
        this.hashChainService = hashChainService;
        this.anonymizationRegistry = anonymizationRegistry;
        this.purgeRegistry = purgeRegistry;
    }

    /** 便捷构造：不带外部链组件时使用独立的内存链（主要供不关注防篡改的既有单测）。 */
    public DefaultAuditService(AuditEventRepository repository,
                               MaskingService maskingService,
                               AuditAccessControl accessControl,
                               AuditProperties properties) {
        this(repository, maskingService, accessControl, properties,
                new HashChainService(new InMemoryChainEntryRepository()),
                new InMemoryAnonymizationRegistry(),
                new InMemoryPurgeRegistry());
    }

    @Override
    public AuditEvent record(String actor, String action, String resourceType, String resourceId,
                             Map<String, Object> parameters, OperationResult result, String reason) {
        return record(actor, action, resourceType, resourceId, parameters, result, reason, 0L);
    }

    @Override
    public AuditEvent record(String actor, String action, String resourceType, String resourceId,
                             Map<String, Object> parameters, OperationResult result, String reason,
                             long durationMillis) {
        String requestId = AuditContext.currentRequestId();
        long sequence;
        if (requestId == null) {
            // 无请求上下文（如单元测试直接调用）时退化为独立上下文，绝不串号。
            requestId = "standalone-" + UUID.randomUUID();
            AuditContext.beginRequest(requestId);
            try {
                sequence = AuditContext.nextSequence();
            } finally {
                AuditContext.endRequest();
            }
        } else {
            sequence = AuditContext.nextSequence();
        }

        String eventId = stableEventId(requestId, sequence);
        Map<String, Object> maskedParameters =
                parameters == null ? Map.of() : maskingService.maskParameters(parameters);

        AuditEvent event = new AuditEvent(
                eventId,
                requestId,
                sequence,
                actor == null || actor.isBlank() ? "anonymous" : actor,
                action,
                resourceType == null ? "" : resourceType,
                resourceId,
                maskedParameters,
                result == null ? OperationResult.ERROR : result,
                truncateReason(reason),
                Instant.now(),
                durationMillis,
                AuditContext.isAsync());

        boolean saved = repository.saveIfAbsent(event);
        if (saved) {
            // 只有真正落库的新记录才入链；同一 eventId 的重试不会产生重复环节点。
            hashChainService.appendIfNew(event);
        }
        return repository.findByEventId(eventId).orElse(event);
    }

    private static String truncateReason(String reason) {
        if (reason == null) {
            return null;
        }
        return reason.length() <= 500 ? reason : reason.substring(0, 500) + "...";
    }

    private static String stableEventId(String requestId, long sequence) {
        String hash = Long.toUnsignedString(
                UUID.nameUUIDFromBytes((requestId + "#" + sequence).getBytes(StandardCharsets.UTF_8))
                        .getMostSignificantBits() & Long.MAX_VALUE, 36);
        return "evt-" + hash;
    }

    @Override
    public AuditPage query(AuditUser user, String requestId, String actor, String action,
                           String resourceType, String resourceId, int limit, long offset) {
        accessControl.checkQuery(user, resourceType, resourceId);
        long total = repository.count(requestId, actor, action, resourceType, resourceId);
        return new AuditPage(
                repository.query(requestId, actor, action, resourceType, resourceId, limit, offset),
                total, clampLimit(limit), offset);
    }

    @Override
    public AuditEvent get(AuditUser user, String eventId) {
        accessControl.checkAuthenticated(user);
        AuditEvent event = repository.findByEventId(eventId)
                .orElseThrow(() -> new IllegalArgumentException("审计记录不存在: " + eventId));
        accessControl.checkRead(user, event);
        return event;
    }

    @Override
    public AuditPage export(AuditUser user, int limit) {
        accessControl.checkExport(user);
        int safeLimit = clampLimit(limit);
        return new AuditPage(repository.findAllOrdered(safeLimit),
                repository.countAll(), safeLimit, 0);
    }

    @Override
    public long purgeExpired() {
        AuditProperties.Retention retention = properties.getRetention();
        Instant cutoff = Instant.now().minus(Duration.ofDays(retention.getDays()));
        if ("ANONYMIZE".equalsIgnoreCase(retention.getPurgeMode())) {
            List<AuditEvent> anonymized = repository.anonymizeOlderThan(cutoff);
            // 正常匿名化会改变记录内容，登记匿名化后的内容哈希，
            // 供完整性校验把“按策略匿名化”与“被篡改”区分开。
            for (AuditEvent event : anonymized) {
                hashChainService.latestAnonymizedAnchor(event.eventId())
                        .ifPresent(previousHash -> anonymizationRegistry.register(
                                event.eventId(), AuditEventHash.compute(event, previousHash)));
            }
            return anonymized.size();
        }
        List<String> deletedIds = repository.deleteOlderThan(cutoff);
        // 正常物理删除先登记，完整性校验据此把“按策略清理”与“人为删除”区分开。
        deletedIds.forEach(purgeRegistry::registerPurged);
        return deletedIds.size();
    }

    private static int clampLimit(int limit) {
        return Math.max(1, Math.min(limit, 500));
    }
}

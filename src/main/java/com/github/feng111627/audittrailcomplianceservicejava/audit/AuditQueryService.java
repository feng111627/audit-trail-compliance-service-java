package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.mask.SensitiveDataMasker;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * 审计数据查询/导出服务。
 *
 * <p><b>越权不是返回空结果，而是明确抛错并带可区分原因：</b>
 * <ul>
 *   <li>没有操作人身份（未登录）→ {@link AccessDeniedReason#NOT_AUTHENTICATED}；</li>
 *   <li>已登录但没有查询角色 → {@link AccessDeniedReason#FORBIDDEN_ROLE}。</li>
 * </ul>
 * 允许查询的角色由 {@code audit.query-roles} 配置，默认 AUDITOR / ADMIN。
 *
 * <p>返回前对 params/reasonDetail 再脱敏一次，确保对外输出永远不含明文敏感内容。
 */
@Service
public class AuditQueryService {

    private final AuditEventRepository repository;
    private final AuditProperties properties;
    private final SensitiveDataMasker masker;

    public AuditQueryService(AuditEventRepository repository, AuditProperties properties,
                             SensitiveDataMasker masker) {
        this.repository = repository;
        this.properties = properties;
        this.masker = masker;
    }

    public List<AuditEvent> query(String traceId, Instant from, Instant to, UserContext requester) {
        authorize(requester);
        List<AuditEvent> events = repository.findAll().stream()
                .filter(e -> traceId == null || traceId.isBlank() || traceId.equals(e.traceId()))
                .filter(e -> from == null || !e.eventTime().isBefore(from))
                .filter(e -> to == null || !e.eventTime().isAfter(to))
                .map(this::reMask)
                .toList();
        return events;
    }

    private void authorize(UserContext requester) {
        if (requester == null || requester.username() == null || requester.username().isBlank()) {
            throw new AccessDeniedException(
                    AccessDeniedReason.NOT_AUTHENTICATED,
                    "未认证：查询审计数据需要先登录");
        }
        boolean allowed = requester.roles() != null
                && requester.roles().stream().anyMatch(properties.getQueryRoles()::contains);
        if (!allowed) {
            throw new AccessDeniedException(
                    AccessDeniedReason.FORBIDDEN_ROLE,
                    "角色越权：用户 '" + requester.username() + "' 的角色 "
                            + (requester.roles() == null ? "[]" : requester.roles())
                            + " 不允许查询审计数据，需要 " + properties.getQueryRoles() + " 之一");
        }
    }

    /** 对外输出前的脱敏兜底：即使存储侧漏过，查询结果也不会出现明文敏感内容。 */
    private AuditEvent reMask(AuditEvent e) {
        return new AuditEvent(
                e.eventId(), e.traceId(), e.spanId(), e.parentSpanId(), e.seq(), e.eventTime(),
                e.actor(), e.actorRoles(), e.action(), e.resourceType(), e.resourceId(),
                e.outcome(), e.reasonCode(),
                e.reasonDetail() == null ? null : masker.mask(e.reasonDetail()),
                e.params() == null ? null : masker.mask(e.params()),
                e.durationMs(), e.threadName(), e.idempotencyKey()
        );
    }
}

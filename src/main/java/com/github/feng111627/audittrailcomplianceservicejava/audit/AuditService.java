package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.mask.SensitiveDataMasker;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * 审计记录统一入口。
 *
 * <p>职责：
 * <ol>
 *   <li>从 {@link AuditContextHolder} 取当前请求上下文（没有时为脱离 Web 的调用建立临时上下文，
 *       保证任何线程、任何入口的操作都不会漏记）；</li>
 *   <li>补齐 eventId、traceId、span、seq、操作人、线程名、事件时间等归属信息；</li>
 *   <li>落库前对 params 再做一次脱敏（纵深防御，切面通常已脱敏）；</li>
 *   <li>交给仓储做幂等写入。</li>
 * </ol>
 */
@Service
public class AuditService {

    private final AuditEventRepository repository;
    private final SensitiveDataMasker masker;

    public AuditService(AuditEventRepository repository, SensitiveDataMasker masker) {
        this.repository = repository;
        this.masker = masker;
    }

    /** 基于当前线程上下文记录一条审计事件。 */
    public AuditEvent record(AuditRecordCommand command) {
        AuditContext context = AuditContextHolder.get();
        if (context == null) {
            // 非 Web / 未经过滤器的调用：建立独立临时上下文，仍然完整留痕。
            context = AuditContext.startNew(null, null);
            AuditContextHolder.set(context);
        }

        long seq = context.nextSeq();
        String spanId = context.currentSpanId();
        String parentSpanId = context.parentSpanIdOfCurrent();
        UserContext user = context.user();
        String actor = user != null ? user.username() : "anonymous";
        Set<String> roles = user != null ? user.roles() : Set.of();

        // 落库前最终一道脱敏：保证敏感内容绝不以明文进入存储。
        String safeParams = command.params() == null ? null : masker.mask(command.params());

        AuditEvent event = new AuditEvent(
                UUID.randomUUID().toString(),
                context.traceId(),
                spanId,
                parentSpanId,
                seq,
                Instant.now(),
                actor,
                roles == null ? Set.of() : Set.copyOf(roles),
                command.action(),
                command.resourceType(),
                command.resourceId(),
                command.outcome(),
                command.reasonCode(),
                command.reasonDetail(),
                safeParams,
                command.durationMs(),
                Thread.currentThread().getName(),
                context.idempotencyKey()
        );
        return repository.save(event);
    }
}

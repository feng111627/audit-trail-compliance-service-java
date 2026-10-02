package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.feng111627.audittrailcomplianceservicejava.audit.config.AuditProperties;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.DefaultMaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.InMemoryAuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.DefaultAuditService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 业务点：留存时长可配置；过期数据按配置物理删除或匿名化，未过期数据保留。
 */
@DisplayName("业务点-留存时长与过期处理")
class RetentionPolicyTest {

    private AuditEvent event(String id, Instant timestamp, String actor) {
        return new AuditEvent(id, "req-" + id, 1, actor, "ORDER_CREATE",
                "ORDER", "ORD-" + id, Map.of("phone", "13812341234"),
                OperationResult.SUCCESS, null, timestamp, 0, false);
    }

    private DefaultAuditService serviceWith(String mode, int days) {
        AuditProperties properties = new AuditProperties();
        properties.getRetention().setPurgeMode(mode);
        properties.getRetention().setDays(days);
        return new DefaultAuditService(new InMemoryAuditEventRepository(),
                new DefaultMaskingService(), new AuditAccessControl(), properties);
    }

    @Test
    @DisplayName("DELETE 模式：超过留存天数的记录被物理删除，未过期的保留")
    void deleteModeRemovesExpired() {
        InMemoryAuditEventRepository repo = new InMemoryAuditEventRepository();
        AuditProperties properties = new AuditProperties();
        properties.getRetention().setPurgeMode("DELETE");
        properties.getRetention().setDays(30);
        DefaultAuditService service = new DefaultAuditService(
                repo, new DefaultMaskingService(), new AuditAccessControl(), properties);

        Instant old = Instant.now().minus(31, ChronoUnit.DAYS);
        Instant recent = Instant.now().minus(1, ChronoUnit.DAYS);
        repo.saveIfAbsent(event("old", old, "alice"));
        repo.saveIfAbsent(event("new", recent, "bob"));

        long purged = service.purgeExpired();

        assertThat(purged).isEqualTo(1);
        assertThat(repo.findByEventId("old")).isEmpty();
        assertThat(repo.findByEventId("new")).isPresent();
    }

    @Test
    @DisplayName("ANONYMIZE 模式：过期记录保留骨架，actor 匿名化、参数清空")
    void anonymizeModeKeepsSkeleton() {
        InMemoryAuditEventRepository repo = new InMemoryAuditEventRepository();
        AuditProperties properties = new AuditProperties();
        properties.getRetention().setPurgeMode("ANONYMIZE");
        properties.getRetention().setDays(30);
        DefaultAuditService service = new DefaultAuditService(
                repo, new DefaultMaskingService(), new AuditAccessControl(), properties);

        repo.saveIfAbsent(event("old", Instant.now().minus(100, ChronoUnit.DAYS), "alice"));

        long purged = service.purgeExpired();

        assertThat(purged).isEqualTo(1);
        AuditEvent kept = repo.findByEventId("old").orElseThrow();
        assertThat(kept.actor()).isEqualTo("deleted@retention");
        assertThat(kept.parameters()).isEmpty();
        // 动作与时间仍保留，满足留存可追溯
        assertThat(kept.action()).isEqualTo("ORDER_CREATE");
    }
}

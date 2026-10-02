package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * 审计数据留存与过期清理。
 *
 * <p>策略（可配置）：
 * <ul>
 *   <li>{@code audit.retention-days}：留存天数，默认 90 天；</li>
 *   <li>{@code audit.purge-cron}：定时清理表达式，默认每天凌晨 2 点；</li>
 *   <li>过期数据处理方式：物理删除（deleteOlderThan 早于 now-retentionDays 的记录）。</li>
 * </ul>
 * 生产环境如需归档，可在删除前增加归档步骤，接口位置即本服务。
 */
@Service
public class RetentionService {

    private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

    private final AuditEventRepository repository;
    private final AuditProperties properties;

    public RetentionService(AuditEventRepository repository, AuditProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    @Scheduled(cron = "${audit.purge-cron:0 0 2 * * ?}")
    public void purgeExpired() {
        int removed = purgeExpiredOnce();
        log.info("审计数据过期清理完成：删除 {} 条，留存策略 {} 天", removed, properties.getRetentionDays());
    }

    /** 执行一次清理并返回删除条数（也便于单测/运维手动触发）。 */
    public int purgeExpiredOnce() {
        if (properties.getRetentionDays() <= 0) {
            // 0 或负数视为永久留存，不做删除，避免误配置清空数据。
            return 0;
        }
        Instant cutoff = Instant.now().minus(Duration.ofDays(properties.getRetentionDays()));
        return repository.deleteOlderThan(cutoff);
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.audit.service;

import com.github.feng111627.audittrailcomplianceservicejava.audit.config.AuditProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 过期审计数据处理。
 * 处理方式由 audit.retention.purge-mode 决定：
 * DELETE（默认，物理删除）或 ANONYMIZE（匿名化 actor 并清空参数，记录骨架保留）。
 */
@Component
public class RetentionService {

    private static final Logger log = LoggerFactory.getLogger(RetentionService.class);

    private final AuditService auditService;
    private final AuditProperties properties;

    public RetentionService(AuditService auditService, AuditProperties properties) {
        this.auditService = auditService;
        this.properties = properties;
    }

    @PostConstruct
    public void purgeOnStartup() {
        if (properties.isEnabled() && properties.getRetention().isPurgeOnStartup()) {
            long n = purgeNow();
            log.info("启动时清理过期审计数据 {} 条（模式={}，留存天数={}）",
                    n, properties.getRetention().getPurgeMode(), properties.getRetention().getDays());
        }
    }

    @Scheduled(cron = "${audit.retention.cron:0 30 2 * * *}")
    public void scheduledPurge() {
        if (properties.isEnabled()) {
            long n = purgeNow();
            log.info("定时清理过期审计数据 {} 条（模式={}，留存天数={}）",
                    n, properties.getRetention().getPurgeMode(), properties.getRetention().getDays());
        }
    }

    public long purgeNow() {
        return auditService.purgeExpired();
    }
}

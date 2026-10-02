package com.github.feng111627.audittrailcomplianceservicejava.audit.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** 启用审计配置属性与定时清理。 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(AuditProperties.class)
public class AuditConfig {
}

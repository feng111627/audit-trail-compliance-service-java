package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.web.HeaderUserContextProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/** 审计能力总配置：注册属性、过滤器、异步与调度开关。 */
@Configuration
@EnableAsync
@EnableScheduling
@EnableConfigurationProperties(AuditProperties.class)
public class AuditConfig {

    @Bean
    public AuditContextFilter auditContextFilter(HeaderUserContextProvider userProvider) {
        return new AuditContextFilter(userProvider);
    }
}

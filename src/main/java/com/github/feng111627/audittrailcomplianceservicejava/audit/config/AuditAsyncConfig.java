package com.github.feng111627.audittrailcomplianceservicejava.audit.config;

import com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import java.util.concurrent.Executor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * 开启异步并提供携带审计上下文的线程池。
 * TaskDecorator 在任务提交时（请求线程内）抓取 requestId/序列号计数器与用户，
 * 在执行线程上恢复，使异步留痕仍归属原请求、共享同一序列号空间。
 */
@Configuration
@EnableAsync
public class AuditAsyncConfig {

    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("audit-async-");
        executor.setTaskDecorator(auditContextTaskDecorator());
        executor.initialize();
        return executor;
    }

    private TaskDecorator auditContextTaskDecorator() {
        return runnable -> {
            // decorate 在提交任务的线程执行，此时上下文完整。
            AuditContext.Snapshot auditSnapshot = AuditContext.snapshot();
            AuditUser userSnapshot = AuditSecurityContext.snapshot();
            return () -> {
                try (AuditContext.Scope ignored = AuditContext.restore(auditSnapshot)) {
                    AuditUser previous = AuditSecurityContext.get();
                    AuditSecurityContext.restore(userSnapshot);
                    try {
                        runnable.run();
                    } finally {
                        AuditSecurityContext.restore(previous);
                    }
                }
            };
        };
    }
}

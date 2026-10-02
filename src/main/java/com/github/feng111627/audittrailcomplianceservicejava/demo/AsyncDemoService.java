package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.service.AuditService;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * 演示异步线程中的手动留痕：请求线程不等待，
 * 但记录仍通过 TaskDecorator 携带的审计上下文归属原 requestId。
 */
@Service
public class AsyncDemoService {

    private final AuditService auditService;

    public AsyncDemoService(AuditService auditService) {
        this.auditService = auditService;
    }

    @Async("auditExecutor")
    public void notifyAsync(String orderId) {
        auditService.record("async-worker", "ORDER_NOTIFY_SENT", "ORDER", orderId,
                java.util.Map.of("channel", "sms"),
                com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult.SUCCESS,
                null);
    }
}

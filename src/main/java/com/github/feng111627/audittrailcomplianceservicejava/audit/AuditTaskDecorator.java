package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.util.function.Supplier;
import org.springframework.core.task.TaskDecorator;
import org.springframework.stereotype.Component;

/**
 * 异步任务装饰器：在任务提交线程捕获 {@link AuditContext} 快照，
 * 在实际执行线程（线程池工作线程）上恢复，执行完务必清理。
 *
 * <p>这样 {@code @Async} 方法里产生的审计记录与原请求共享 traceId，
 * span 父子关系也保留；线程池线程复用时不会把上一个任务的上下文遗留下来。
 *
 * <p>快照是深拷贝语义：工作线程拥有独立 span 栈与 seq 计数器，
 * 不会与主线程或其他并发任务互相干扰。
 */
@Component
public class AuditTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        AuditContext snapshot = AuditContextHolder.get();
        return () -> {
            AuditContext previous = AuditContextHolder.get();
            if (snapshot != null) {
                AuditContextHolder.set(snapshot.snapshotForAsync());
            }
            try {
                runnable.run();
            } finally {
                if (previous != null) {
                    AuditContextHolder.set(previous);
                } else {
                    AuditContextHolder.clear();
                }
            }
        };
    }
}

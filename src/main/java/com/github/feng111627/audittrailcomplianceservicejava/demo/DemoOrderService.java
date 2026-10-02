package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Audited;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.stereotype.Service;

/** 演示用订单业务，关键操作均带 @Audited。 */
@Service
public class DemoOrderService {

    private final ConcurrentMap<String, Order> orders = new ConcurrentHashMap<>();
    private final AsyncDemoService asyncDemoService;

    public DemoOrderService(AsyncDemoService asyncDemoService) {
        this.asyncDemoService = asyncDemoService;
    }

    @Audited(action = "ORDER_CREATE", resourceType = "ORDER", resourceId = "#result.id()")
    public Order createOrder(CreateOrderRequest request) {
        String id = "ORD-" + UUID.randomUUID().toString().substring(0, 8);
        Order order = new Order(id, request.owner(), request.product(), request.phone());
        orders.put(id, order);
        // 触发一次异步操作，验证上下文跨线程传递。
        asyncDemoService.notifyAsync(id);
        return order;
    }

    @Audited(action = "ORDER_UPDATE_PHONE", resourceType = "ORDER", resourceId = "#id")
    public Order updatePhone(String id, UpdatePhoneRequest request) {
        Order existing = requireOwned(id);
        Order updated = new Order(existing.id(), existing.owner(), existing.product(), request.phone());
        orders.put(id, updated);
        return updated;
    }

    @Audited(action = "ORDER_CANCEL", resourceType = "ORDER", resourceId = "#id")
    public Order cancel(String id) {
        Order existing = requireOwned(id);
        orders.remove(id);
        return existing;
    }

    @Audited(action = "ORDER_QUERY", resourceType = "ORDER", resourceId = "#id")
    public Order get(String id) {
        return requireOwned(id);
    }

    @Audited(action = "ORDER_TRIGGER_ERROR", resourceType = "ORDER")
    public Order triggerError() {
        throw new IllegalStateException("模拟系统异常中断");
    }

    @Audited(action = "ORDER_ASYNC_NOTIFY", resourceType = "ORDER", resourceId = "#id")
    public void asyncNotify(String id) {
        asyncDemoService.notifyAsync(id);
    }

    /** 订单必须属于当前用户，否则业务拒绝（FAILED）。 */
    private Order requireOwned(String id) {
        Order existing = orders.get(id);
        if (existing == null) {
            throw new BusinessException("订单不存在: " + id);
        }
        if (!existing.owner().equals(currentUser())) {
            throw new BusinessException("无权操作他人订单: " + id);
        }
        return existing;
    }

    public ConcurrentMap<String, Order> store() {
        return orders;
    }

    String currentUser() {
        var u = AuditSecurityContext.get();
        return u == null ? "anonymous" : u.username();
    }
}

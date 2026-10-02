package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 演示业务的 HTTP 入口。审计记录由切面自动完成，控制器无需手写留痕代码。 */
@RestController
@RequestMapping("/api/demo/orders")
public class DemoOrderController {

    private final DemoOrderService orderService;

    public DemoOrderController(DemoOrderService orderService) {
        this.orderService = orderService;
    }

    @PostMapping
    public ResponseEntity<String> place(@RequestBody PlaceOrderRequest request) {
        return ResponseEntity.ok(orderService.placeOrder(request));
    }

    @PostMapping("/{orderId}/cancel")
    public ResponseEntity<String> cancel(@PathVariable String orderId) {
        return ResponseEntity.ok(orderService.cancelOrder(orderId));
    }

    @PostMapping("/{orderId}/approve")
    public ResponseEntity<String> approve(@PathVariable String orderId) {
        return ResponseEntity.ok(orderService.approveOrder(orderId));
    }

    @PostMapping("/{orderId}/risk")
    public ResponseEntity<String> risk(@PathVariable String orderId) {
        return ResponseEntity.ok(orderService.riskyUpdate(orderId));
    }

    @PostMapping("/{orderId}/async")
    public ResponseEntity<String> async(@PathVariable String orderId) {
        orderService.processAsync(orderId);
        return ResponseEntity.accepted()
                .header("X-Trace-Id", AuditContextHolder.get().traceId())
                .build();
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.demo;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 业务入口。@Valid 校验失败会被全局处理器记录为 VALIDATION_REJECTED。 */
@RestController
@RequestMapping("/api/orders")
public class DemoOrderController {

    private final DemoOrderService orderService;

    public DemoOrderController(DemoOrderService orderService) {
        this.orderService = orderService;
    }

    @PostMapping
    public Order create(@Valid @RequestBody CreateOrderRequest request) {
        return orderService.createOrder(request);
    }

    @PostMapping("/{id}/phone")
    public Order updatePhone(@PathVariable String id, @Valid @RequestBody UpdatePhoneRequest request) {
        return orderService.updatePhone(id, request);
    }

    @PostMapping("/{id}/cancel")
    public Order cancel(@PathVariable String id) {
        return orderService.cancel(id);
    }
}

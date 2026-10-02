package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import com.github.feng111627.audittrailcomplianceservicejava.demo.BusinessException;
import com.github.feng111627.audittrailcomplianceservicejava.demo.CreateOrderRequest;
import com.github.feng111627.audittrailcomplianceservicejava.demo.DemoOrderService;
import com.github.feng111627.audittrailcomplianceservicejava.demo.Order;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 业务点：正常操作留痕、业务失败（被拒绝）、异常中断、敏感参数落库即脱敏、
 * 同请求内事件归属同一 requestId 且序列号单调。
 */
@SpringBootTest
@DisplayName("业务点-关键操作自动留痕")
class AuditRecordingTest {

    @Autowired
    private DemoOrderService orderService;

    @Autowired
    private AuditEventRepository repository;

    private String requestId;

    @BeforeEach
    void setUp() {
        requestId = "req-" + UUID.randomUUID();
        AuditContext.beginRequest(requestId);
        AuditSecurityContext.set(new AuditUser("alice", "Alice", Set.of(Roles.USER)));
    }

    @AfterEach
    void tearDown() {
        AuditContext.endRequest();
        AuditSecurityContext.clear();
    }

    @Test
    @DisplayName("正常创建订单：记录为 SUCCESS，含操作人/资源ID/动作，且参数已脱敏")
    void successIsRecorded() {
        CreateOrderRequest request = new CreateOrderRequest(
                "alice", "《审计实战》", "13812341234", "paypass");
        Order order = orderService.createOrder(request);

        AuditEvent event = repository.query(null, "alice", "ORDER_CREATE",
                "ORDER", order.id(), 10, 0).stream().findFirst().orElseThrow();

        assertThat(event.result()).isEqualTo(OperationResult.SUCCESS);
        assertThat(event.actor()).isEqualTo("alice");
        assertThat(event.resourceId()).isEqualTo(order.id());
        assertThat(event.requestId()).isEqualTo(requestId);
        assertThat(event.sequence()).isGreaterThan(0);
        // 参数落库即脱敏：原始手机号/密码不得出现
        String params = event.parameters().toString();
        assertThat(params).contains("138****1234").contains("******");
        assertThat(params).doesNotContain("13812341234").doesNotContain("paypass");
    }

    @Test
    @DisplayName("操作他人订单触发业务拒绝：记录为 FAILED 且能看到拒绝原因")
    void businessFailureIsRecorded() {
        // 先用 alice 建单
        Order order = orderService.createOrder(new CreateOrderRequest(
                "alice", "book", "13812341234", "paypass"));
        // 换成 bob 操作
        AuditSecurityContext.set(new AuditUser("bob", "Bob", Set.of(Roles.USER)));

        assertThatThrownBy(() -> orderService.cancel(order.id()))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("无权操作他人订单");

        AuditEvent event = repository.query(null, "bob", "ORDER_CANCEL",
                "ORDER", order.id(), 10, 0).stream().findFirst().orElseThrow();
        assertThat(event.result()).isEqualTo(OperationResult.FAILED);
        assertThat(event.reason()).contains("[业务拒绝]").contains("无权操作他人订单");
    }

    @Test
    @DisplayName("系统异常中断：记录为 ERROR，异常照样向上抛出且不丢记录")
    void errorIsRecorded() {
        assertThatThrownBy(() -> orderService.triggerError())
                .isInstanceOf(IllegalStateException.class);

        List<AuditEvent> events = repository.query(requestId, null,
                "ORDER_TRIGGER_ERROR", null, null, 10, 0);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).result()).isEqualTo(OperationResult.ERROR);
        assertThat(events.get(0).reason()).contains("[异常中断]");
    }

    @Test
    @DisplayName("同一次请求的多条记录共享 requestId，序列号单调递增且无重复")
    void sequenceWithinRequest() {
        orderService.createOrder(new CreateOrderRequest(
                "alice", "a", "13812341234", "paypass"));
        try {
            orderService.triggerError();
        } catch (IllegalStateException expected) {
            // 预期异常，继续验证同一请求内的序列号
        }

        List<AuditEvent> events = repository.query(requestId, null, null, null, null, 50, 0);
        assertThat(events).allSatisfy(e -> assertThat(e.requestId()).isEqualTo(requestId));

        List<Long> sequences = events.stream().map(AuditEvent::sequence).sorted().toList();
        assertThat(sequences).doesNotHaveDuplicates();
        assertThat(sequences).isSorted();

        long distinctIds = events.stream().map(AuditEvent::eventId).distinct().count();
        assertThat(distinctIds).isEqualTo(events.size());
    }
}

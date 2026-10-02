package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContextHolder;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditOutcome;
import com.github.feng111627.audittrailcomplianceservicejava.audit.Audited;
import com.github.feng111627.audittrailcomplianceservicejava.audit.BusinessFailureException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.UserContext;
import com.github.feng111627.audittrailcomplianceservicejava.demo.DemoOrderService;
import com.github.feng111627.audittrailcomplianceservicejava.demo.PlaceOrderRequest;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.stereotype.Component;

/** 自动留痕的结果分类测试：成功、业务失败、校验拒绝、异常中断、嵌套归属。 */
@SpringBootTest
@DisplayName("自动留痕：成功/失败/拒绝/中断 结果分类与内容")
class AuditTrailOutcomeTest {

    @Autowired
    private DemoOrderService orderService;

    @Autowired
    private AuditEventRepository repository;

    @Autowired
    private NestedService nestedService;

    /** 用于验证同一请求内多个嵌套操作的 span 归属与先后顺序。 */
    @Component
    static class NestedService {

        private final DemoOrderService orderService;

        NestedService(DemoOrderService orderService) {
            this.orderService = orderService;
        }

        @Audited(action = "OUTER_OP", resourceType = "BATCH")
        public String runOuter(String orderId) {
            return "OUTER->" + orderService.cancelOrder(orderId);
        }
    }

    @BeforeEach
    void setUp() {
        repository.deleteOlderThan(Instant.now().plusSeconds(1));
        AuditContextHolder.set(AuditContext.startNew(
                new UserContext("alice", Set.of("USER")), "key-outcome"));
    }

    private List<AuditEvent> events() {
        return repository.findAll();
    }

    @Nested
    @DisplayName("场景：正常操作留痕")
    class HappyPath {

        @Test
        @DisplayName("下单成功：记录 SUCCESS，含操作人/动作/资源/耗时，参数中手机号与证件号已脱敏")
        void 下单成功完整留痕() {
            PlaceOrderRequest req = new PlaceOrderRequest(
                    "O-1001", "张三", "13812348000", "11010119900307123X");
            String result = orderService.placeOrder(req);

            assertEquals("PLACED:O-1001", result);
            AuditEvent e = events().get(0);
            assertEquals(AuditOutcome.SUCCESS, e.outcome());
            assertEquals("ORDER_PLACE", e.action());
            assertEquals("ORDER", e.resourceType());
            assertEquals("O-1001", e.resourceId());
            assertEquals("alice", e.actor());
            assertEquals("OK", e.reasonCode());
            assertTrue(e.durationMs() >= 0);
            assertNotNull(e.eventId());
            // 敏感数据不能明文落库
            assertTrue(e.params().contains("138****8000"));
            assertTrue(e.params().contains("110101********123X"));
            assertTrue(!e.params().contains("13812348000"));
        }
    }

    @Nested
    @DisplayName("场景：失败与拒绝不能被悄悄丢掉")
    class Failures {

        @Test
        @DisplayName("手机号格式不对：记为 VALIDATION_REJECTED（被拒绝），异常照常抛出")
        void 参数校验失败被记录为拒绝() {
            PlaceOrderRequest req = new PlaceOrderRequest("O-1002", "李四", "123", "11010119900307123X");
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> orderService.placeOrder(req));

            AuditEvent e = events().get(0);
            assertEquals(AuditOutcome.VALIDATION_REJECTED, e.outcome());
            assertEquals("VALIDATION_REJECTED", e.reasonCode());
            assertTrue(e.reasonDetail().contains("手机号格式不正确"));
            assertTrue(ex.getMessage().contains("手机号格式不正确"));
        }

        @Test
        @DisplayName("命中黑名单：记为 FAILURE（业务规则拒绝），可看出拒绝原因")
        void 业务失败被记录() {
            PlaceOrderRequest req = new PlaceOrderRequest(
                    "BLK001", "王五", "13812348000", "11010119900307123X");
            assertThrows(BusinessFailureException.class, () -> orderService.placeOrder(req));

            AuditEvent e = events().get(0);
            assertEquals(AuditOutcome.FAILURE, e.outcome());
            assertEquals("BUSINESS_FAILURE", e.reasonCode());
            assertTrue(e.reasonDetail().contains("黑名单"));
        }

        @Test
        @DisplayName("订单已完结不能取消：同样记为 FAILURE")
        void 取消已完结订单记为业务失败() {
            assertThrows(BusinessFailureException.class, () -> orderService.cancelOrder("X-9"));
            assertEquals(AuditOutcome.FAILURE, events().get(0).outcome());
        }

        @Test
        @DisplayName("系统异常：记为 ERROR（被中断），reasonCode 带异常类型，异常继续向上抛")
        void 系统异常记为中断() {
            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> orderService.riskyUpdate("O-7"));

            AuditEvent e = events().get(0);
            assertEquals(AuditOutcome.ERROR, e.outcome());
            assertEquals("ERROR:IllegalStateException", e.reasonCode());
            assertTrue(e.reasonDetail().contains("风控系统不可用"));
            assertTrue(ex.getMessage().contains("风控系统不可用"));
        }
    }

    @Nested
    @DisplayName("场景：一次请求多个操作的归属")
    class Nesting {

        @Test
        @DisplayName("外层操作调用内层操作：两条记录同 traceId，内层 parentSpanId 指向外层 spanId，seq 先后递增")
        void 嵌套操作归属与先后正确() {
            nestedService.runOuter("O-2001");

            List<AuditEvent> list = events();
            assertEquals(2, list.size());
            AuditEvent inner = list.stream().filter(x -> "ORDER_CANCEL".equals(x.action())).findFirst().orElseThrow();
            AuditEvent outer = list.stream().filter(x -> "OUTER_OP".equals(x.action())).findFirst().orElseThrow();

            assertEquals(outer.traceId(), inner.traceId());
            assertEquals(outer.spanId(), inner.parentSpanId());
            // seq 在事件落库时按完成顺序分配：内层先完成取 1，外层后完成取 2
            assertEquals(1, inner.seq());
            assertEquals(2, outer.seq());
        }
    }
}

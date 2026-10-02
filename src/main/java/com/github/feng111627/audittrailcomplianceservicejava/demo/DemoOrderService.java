package com.github.feng111627.audittrailcomplianceservicejava.demo;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AccessDeniedReason;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContextHolder;
import com.github.feng111627.audittrailcomplianceservicejava.audit.Audited;
import com.github.feng111627.audittrailcomplianceservicejava.audit.BusinessFailureException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AccessDeniedException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.UserContext;
import java.util.Set;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * 演示业务服务，覆盖全部审计结果类型：
 * 成功（placeOrder）、校验拒绝（非法参数）、业务失败（黑名单）、
 * 越权拒绝（approveOrder 需 ADMIN）、异常中断（riskyUpdate 抛系统异常）、
 * 以及异步操作（processAsync，验证上下文跨线程传递）。
 */
@Service
public class DemoOrderService {

    private static final Set<String> BLACKLIST = Set.of("BLK001");

    @Audited(action = "ORDER_PLACE", resourceType = "ORDER", resourceIdExpr = "#request.orderId()")
    public String placeOrder(PlaceOrderRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("下单请求不能为空");
        }
        if (request.orderId() == null || request.orderId().isBlank()) {
            throw new IllegalArgumentException("订单号不能为空");
        }
        if (request.phone() == null || !request.phone().matches("1[3-9]\\d{9}")) {
            throw new IllegalArgumentException("手机号格式不正确: " + request.phone());
        }
        if (request.idCard() == null || !request.idCard().matches("\\d{17}[0-9Xx]")) {
            throw new IllegalArgumentException("证件号格式不正确");
        }
        if (BLACKLIST.contains(request.orderId())) {
            throw new BusinessFailureException("客户命中黑名单，订单被业务规则拒绝: " + request.orderId());
        }
        return "PLACED:" + request.orderId();
    }

    @Audited(action = "ORDER_CANCEL", resourceType = "ORDER", resourceIdExpr = "#orderId")
    public String cancelOrder(String orderId) {
        if (orderId == null || orderId.isBlank()) {
            throw new IllegalArgumentException("订单号不能为空");
        }
        if (orderId.startsWith("X")) {
            // 业务失败：订单状态不允许取消。
            throw new BusinessFailureException("订单已完结，不能取消: " + orderId);
        }
        return "CANCELLED:" + orderId;
    }

    @Audited(action = "ORDER_APPROVE", resourceType = "ORDER", resourceIdExpr = "#orderId")
    public String approveOrder(String orderId) {
        UserContext user = AuditContextHolder.get() == null ? null : AuditContextHolder.get().user();
        if (user == null) {
            throw new AccessDeniedException(AccessDeniedReason.NOT_AUTHENTICATED, "审批需要登录");
        }
        if (!user.roles().contains("ADMIN")) {
            throw new AccessDeniedException(AccessDeniedReason.FORBIDDEN_ROLE,
                    "审批订单需要 ADMIN 角色，当前用户: " + user.username());
        }
        return "APPROVED:" + orderId;
    }

    @Audited(action = "ORDER_RISK_UPDATE", resourceType = "ORDER", resourceIdExpr = "#orderId")
    public String riskyUpdate(String orderId) {
        // 模拟意料之外的系统异常：操作被中断，但仍必须留痕。
        throw new IllegalStateException("风控系统不可用，处理中断，订单: " + orderId);
    }

    @Async
    @Audited(action = "ORDER_ASYNC_PROCESS", resourceType = "ORDER", resourceIdExpr = "#orderId")
    public void processAsync(String orderId) {
        if (orderId == null || orderId.isBlank()) {
            throw new IllegalArgumentException("异步处理订单号不能为空");
        }
        // 正常情况下只留痕；异常也会被切面记录（异步线程内）。
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEventRepository;
import java.time.Instant;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** HTTP 全链路：过滤器建上下文、切面留痕、查询鉴权、trace 与幂等头透传。 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("HTTP 全链路留痕与鉴权")
class AuditHttpIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteOlderThan(Instant.now().plusSeconds(1));
    }

    @Test
    @DisplayName("下单成功后用响应中的 traceId 查询：能查到该请求的 SUCCESS 记录，且敏感字段已脱敏")
    void 下单再按trace查询() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/demo/orders")
                        .header("X-User", "alice").header("X-Roles", "USER")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"orderId":"O-WEB-1","customerName":"张三",
                                 "phone":"13812348000","idCard":"11010119900307123X"}
                                """))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-Trace-Id"))
                .andReturn();
        String traceId = result.getResponse().getHeader("X-Trace-Id");

        mockMvc.perform(get("/api/audit/events").param("traceId", traceId)
                        .header("X-User", "auditor1").header("X-Roles", "AUDITOR"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].action").value("ORDER_PLACE"))
                .andExpect(jsonPath("$[0].outcome").value("SUCCESS"))
                .andExpect(jsonPath("$[0].traceId").value(traceId))
                .andExpect(jsonPath("$[0].actor").value("alice"))
                .andExpect(jsonPath("$[0].params", Matchers.containsString("138****8000")))
                .andExpect(jsonPath("$[0].params",
                        Matchers.not(Matchers.containsString("13812348000"))));
    }

    @Test
    @DisplayName("同一 Idempotency-Key 重试两次：审计记录只有一条")
    void http重试幂等去重() throws Exception {
        byte[] body = "{\"orderId\":\"O-WEB-2\"}".getBytes(); // 校验会失败，但仍留痕，便于计数
        for (int i = 0; i < 2; i++) {
            mockMvc.perform(post("/api/demo/orders")
                            .header("X-User", "alice")
                            .header("Idempotency-Key", "web-key-9")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isBadRequest());
        }
        long count = repository.findAll().stream()
                .filter(e -> "ORDER_PLACE".equals(e.action())).count();
        assertEquals(1, count);
    }

    @Test
    @DisplayName("无身份查询审计：403 且 reasonCode 为 ACCESS_DENIED_NOT_AUTHENTICATED")
    void 未认证查询返回403并带原因() throws Exception {
        mockMvc.perform(get("/api/audit/events"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reasonCode").value("ACCESS_DENIED_NOT_AUTHENTICATED"));
    }

    @Test
    @DisplayName("普通角色查询审计：403 且 reasonCode 为 ACCESS_DENIED_FORBIDDEN_ROLE（与未认证可区分）")
    void 越权角色返回403并带不同原因() throws Exception {
        mockMvc.perform(get("/api/audit/events")
                        .header("X-User", "bob").header("X-Roles", "USER"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reasonCode").value("ACCESS_DENIED_FORBIDDEN_ROLE"))
                .andExpect(jsonPath("$.message", Matchers.containsString("bob")));
    }

    @Test
    @DisplayName("参数校验失败 400+VALIDATION_REJECTED；业务失败 409+BUSINESS_FAILURE；系统异常 500+ERROR 原因")
    void 拒绝_业务失败_异常的http语义() throws Exception {
        mockMvc.perform(post("/api/demo/orders")
                        .header("X-User", "alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"orderId\":\"O\",\"phone\":\"bad\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reasonCode").value("VALIDATION_REJECTED"));

        // 取消已完结订单（orderId 以 X 开头）→ 业务失败
        mockMvc.perform(post("/api/demo/orders/X-9/cancel")
                        .header("X-User", "alice"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reasonCode").value("BUSINESS_FAILURE"));

        // 黑名单下单 → 业务失败
        mockMvc.perform(post("/api/demo/orders")
                        .header("X-User", "alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"orderId":"BLK001","customerName":"王五",
                                 "phone":"13812348000","idCard":"11010119900307123X"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reasonCode").value("BUSINESS_FAILURE"))
                .andExpect(jsonPath("$.message", Matchers.containsString("黑名单")));

        // 风控异常 → 操作被中断
        mockMvc.perform(post("/api/demo/orders/O-7/risk")
                        .header("X-User", "alice"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.reasonCode").value("ERROR:IllegalStateException"));
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 业务点（HTTP 端到端）：完整性校验入口按角色开放，
 * 返回整体是否完整、覆盖量与第一处异常位置。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("业务点-完整性校验HTTP入口")
class IntegrityEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("审计员发起校验：200，返回 intact 与覆盖量字段")
    void auditorCanVerify() throws Exception {
        // 先制造一条留痕，让校验有内容可覆盖
        mockMvc.perform(post("/api/orders")
                        .header("X-User", "alice").header("X-Roles", Roles.USER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"owner\":\"alice\",\"product\":\"book\","
                                + "\"phone\":\"13812341234\",\"payPassword\":\"paypass\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/audit/integrity/verify")
                        .header("X-User", "auditor").header("X-Roles", Roles.AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.checkedPositions").isNumber())
                .andExpect(jsonPath("$.verifiedCount").isNumber())
                .andExpect(jsonPath("$.legacyCount").isNumber())
                .andExpect(jsonPath("$.purgedCount").isNumber());
    }

    @Test
    @DisplayName("带时间范围参数的校验：200 且只覆盖范围内记录")
    void verifyWithTimeRange() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify")
                        .param("from", "2026-01-01T00:00:00Z")
                        .param("to", "2026-12-31T23:59:59Z")
                        .header("X-User", "root").header("X-Roles", Roles.ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").isBoolean());
    }

    @Test
    @DisplayName("按链上位置区间校验：200，返回区间覆盖量")
    void verifyWithPositionRange() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify-range")
                        .param("fromPosition", "1").param("toPosition", "10")
                        .header("X-User", "auditor").header("X-Roles", Roles.AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").isBoolean())
                .andExpect(jsonPath("$.checkedPositions").isNumber());
    }

    @Test
    @DisplayName("位置区间参数不合法（toPosition < fromPosition）：400")
    void verifyWithInvalidPositionRange() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify-range")
                        .param("fromPosition", "5").param("toPosition", "2")
                        .header("X-User", "auditor").header("X-Roles", Roles.AUDITOR))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("普通用户按区间校验：403 且 reason=INTEGRITY_VERIFY_FORBIDDEN")
    void userVerifyRangeRejected() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify-range")
                        .param("fromPosition", "1")
                        .header("X-User", "bob").header("X-Roles", Roles.USER))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("INTEGRITY_VERIFY_FORBIDDEN"));
    }

    @Test
    @DisplayName("普通用户发起校验：403 且 reason=INTEGRITY_VERIFY_FORBIDDEN")
    void userVerifyRejected() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify")
                        .header("X-User", "bob").header("X-Roles", Roles.USER))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("INTEGRITY_VERIFY_FORBIDDEN"));
    }

    @Test
    @DisplayName("未认证发起校验：401 且 reason=UNAUTHENTICATED")
    void unauthenticatedVerifyRejected() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
    }
}

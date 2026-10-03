package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 业务点（HTTP 端到端）：完整性校验入口按角色放行/拒绝，
 * 返回整体是否完整、覆盖记录数与第一处异常位置。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("业务点-完整性校验入口的访问控制")
class IntegrityVerifyWebTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("未认证调用完整性校验：401 且 reason=UNAUTHENTICATED")
    void unauthenticatedVerifyRejected() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("普通用户调用完整性校验：403 拒绝")
    void userVerifyRejected() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify")
                        .header("X-User", "bob")
                        .header("X-Roles", Roles.USER))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("审计员调用完整性校验：200，返回 intact 与覆盖统计")
    void auditorVerifyAllowed() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify")
                        .header("X-User", "auditor")
                        .header("X-Roles", Roles.AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.scannedCount").isNumber())
                .andExpect(jsonPath("$.legacyCount").isNumber());
    }

    @Test
    @DisplayName("管理员按链上序号范围校验：200，返回链段范围")
    void adminVerifyWithIndexRange() throws Exception {
        mockMvc.perform(get("/api/audit/integrity/verify")
                        .param("fromIndex", "0")
                        .param("toIndex", "1")
                        .header("X-User", "root")
                        .header("X-Roles", Roles.ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").isBoolean());
    }
}

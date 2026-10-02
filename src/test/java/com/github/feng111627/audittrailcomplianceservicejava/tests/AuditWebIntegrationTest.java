package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.repository.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 业务点（HTTP 端到端）：
 * 1) 参数校验未通过返回 400 且审计里出现 VALIDATION_REJECTED；
 * 2) 审计查询/导出按角色拒绝，且响应带可区分 reason，而非静默空结果。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("业务点-校验拒绝留痕与HTTP层越权控制")
class AuditWebIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditEventRepository repository;

    @Test
    @DisplayName("手机号格式不合法：返回400 VALIDATION_REJECTED，并落一条校验拒绝审计")
    void validationFailureIsAudited() throws Exception {
        String body = """
                {"owner":"alice","product":"book","phone":"123","payPassword":"123456"}
                """;

        mockMvc.perform(post("/api/orders")
                        .header("X-User", "alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.result").value("VALIDATION_REJECTED"))
                .andExpect(jsonPath("$.fieldErrors.phone").exists());

        // 校验被拒绝的请求不应被悄悄丢掉
        boolean found = repository.query(null, "alice", "HTTP_REQUEST_VALIDATION",
                        null, null, 50, 0).stream()
                .map(AuditEvent::result)
                .anyMatch(OperationResult.VALIDATION_REJECTED::equals);
        org.assertj.core.api.Assertions.assertThat(found).isTrue();
    }

    @Test
    @DisplayName("无身份访问审计查询：401 且 reason=UNAUTHENTICATED")
    void unauthenticatedQueryRejected() throws Exception {
        mockMvc.perform(get("/api/audit/events"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.denied").value(true))
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("普通用户不带资源条件查询：403 且 reason=MISSING_QUERY_CRITERIA")
    void userBroadQueryRejected() throws Exception {
        mockMvc.perform(get("/api/audit/events")
                        .header("X-User", "bob")
                        .header("X-Roles", Roles.USER))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("MISSING_QUERY_CRITERIA"));
    }

    @Test
    @DisplayName("审计员导出：403 且 reason=EXPORT_FORBIDDEN")
    void auditorExportRejected() throws Exception {
        mockMvc.perform(get("/api/audit/events/export")
                        .header("X-User", "auditor")
                        .header("X-Roles", Roles.AUDITOR))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("EXPORT_FORBIDDEN"));
    }

    @Test
    @DisplayName("管理员导出：200 且返回记录")
    void adminExportAllowed() throws Exception {
        mockMvc.perform(get("/api/audit/events/export")
                        .header("X-User", "root")
                        .header("X-Roles", Roles.ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray());
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.feng111627.audittrailcomplianceservicejava.audit.AccessDeniedException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AccessDeniedReason;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditContextHolder;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditEventRepository;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditProperties;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditQueryService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditRecordCommand;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditOutcome;
import com.github.feng111627.audittrailcomplianceservicejava.audit.AuditService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.RetentionService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.UserContext;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/** 审计数据查询的角色控制、越权原因区分、输出脱敏与留存清理。 */
@SpringBootTest(properties = "audit.retention-days=30")
@DisplayName("查询鉴权与留存：越权明确拒绝、原因可区分、输出脱敏、过期清理")
class AuditAccessControlTest {

    @Autowired
    private AuditQueryService queryService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditEventRepository repository;

    @Autowired
    private AuditProperties properties;

    @Autowired
    private RetentionService retentionService;

    private UserContext auditor() {
        return new UserContext("auditor1", Set.of("AUDITOR"));
    }

    @BeforeEach
    void prepare() {
        repository.deleteOlderThan(Instant.now().plusSeconds(1));
        AuditContextHolder.set(AuditContext.startNew(null, null));
        // 直接提交一条“带明文敏感内容”的记录，模拟存储侧兜底场景
        auditService.record(new AuditRecordCommand("TEST_ACTION", "TEST", "R-1",
                "phone=13812348000, password=SuperSecret", AuditOutcome.SUCCESS, "OK", null, 1));
        AuditContextHolder.clear();
    }

    @Nested
    @DisplayName("场景：按角色控制查询/导出")
    class Authorization {

        @Test
        @DisplayName("AUDITOR 角色可查询并看到记录")
        void 审计员可查() {
            List<AuditEvent> result = queryService.query(null, null, null, auditor());
            assertEquals(1, result.size());
            assertEquals("TEST_ACTION", result.get(0).action());
        }

        @Test
        @DisplayName("ADMIN 角色可查询（默认允许角色之一）")
        void 管理员可查() {
            List<AuditEvent> result = queryService.query(null, null, null,
                    new UserContext("admin1", Set.of("ADMIN")));
            assertEquals(1, result.size());
        }

        @Test
        @DisplayName("未认证访问：抛 NOT_AUTHENTICATED，而不是静默返回空结果")
        void 未认证被明确拒绝() {
            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> queryService.query(null, null, null, null));
            assertEquals(AccessDeniedReason.NOT_AUTHENTICATED, ex.reason());
            assertTrue(ex.getMessage().contains("未认证"));
        }

        @Test
        @DisplayName("普通 USER 角色：抛 FORBIDDEN_ROLE，原因与未认证不同")
        void 越权角色被明确拒绝() {
            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> queryService.query(null, null, null,
                            new UserContext("bob", Set.of("USER"))));
            assertEquals(AccessDeniedReason.FORBIDDEN_ROLE, ex.reason());
            assertTrue(ex.getMessage().contains("ADMIN") || ex.getMessage().contains("AUDITOR"));
        }

        @Test
        @DisplayName("可配置允许角色：把 USER 加入配置后即可查询")
        void 允许角色可配置() {
            List<String> original = properties.getQueryRoles();
            properties.setQueryRoles(List.of("USER"));
            try {
                List<AuditEvent> result = queryService.query(null, null, null,
                        new UserContext("bob", Set.of("USER")));
                assertEquals(1, result.size());
            } finally {
                properties.setQueryRoles(original);
            }
        }
    }

    @Nested
    @DisplayName("场景：输出脱敏与过滤")
    class OutputSafety {

        @Test
        @DisplayName("查询返回前再次脱敏：手机号打码、密码不落为明文")
        void 输出前兜底脱敏() {
            List<AuditEvent> result = queryService.query(null, null, null, auditor());
            String params = result.get(0).params();
            assertTrue(params.contains("138****8000"));
            assertFalse(params.contains("SuperSecret"));
            assertFalse(params.contains("13812348000"));
        }

        @Test
        @DisplayName("按 traceId 过滤只能查到本请求的记录")
        void 按trace过滤() {
            AuditContextHolder.set(AuditContext.startNew(null, null));
            auditService.record(new AuditRecordCommand("OTHER", "T", "R-2", null,
                    AuditOutcome.SUCCESS, "OK", null, 1));
            String otherTrace = AuditContextHolder.get().traceId();
            AuditContextHolder.clear();

            List<AuditEvent> first = queryService.query(null, null, null, auditor());
            assertEquals(2, first.size());
            List<AuditEvent> onlyOther = queryService.query(otherTrace, null, null, auditor());
            assertEquals(1, onlyOther.size());
            assertEquals("OTHER", onlyOther.get(0).action());
        }
    }

    @Nested
    @DisplayName("场景：留存时长与过期处理")
    class Retention {

        @Test
        @DisplayName("超过留存天数的旧数据被物理删除，未过期的保留")
        void 过期数据清理() throws Exception {
            assertEquals(30, properties.getRetentionDays());
            // 直接写入一条 31 天前的记录和一条 1 天前的记录
            insertOldEvent("OLD-1", Instant.now().minusSeconds(31L * 24 * 3600));
            insertOldEvent("NEW-1", Instant.now().minusSeconds(24 * 3600));

            int removed = retentionService.purgeExpiredOnce();
            assertEquals(1, removed);
            List<AuditEvent> remain = repository.findAll();
            assertTrue(remain.stream().noneMatch(e -> "OLD-1".equals(e.resourceId())));
            assertTrue(remain.stream().anyMatch(e -> "NEW-1".equals(e.resourceId())));
        }

        @Test
        @DisplayName("retention-days 配置为非正数时视为永久留存，不删除任何数据")
        void 非正数表示永久留存() {
            int original = properties.getRetentionDays();
            properties.setRetentionDays(0);
            try {
                assertEquals(0, retentionService.purgeExpiredOnce());
                assertTrue(!repository.findAll().isEmpty());
            } finally {
                properties.setRetentionDays(original);
            }
        }

        private void insertOldEvent(String resourceId, Instant time) {
            repository.save(new AuditEvent(
                    java.util.UUID.randomUUID().toString(), "old-trace-" + resourceId,
                    "s1", null, 1, time, "old-user", Set.of(), "OLD_ACTION", "TEST",
                    resourceId, AuditOutcome.SUCCESS, "OK", null, null, 0, "test", null));
        }
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AccessDeniedReason;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessDeniedException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 业务点：查询/读取/导出按角色控制；越权必须被明确拒绝并给出可区分原因。
 */
@DisplayName("业务点-角色化访问控制")
class AuditAccessControlTest {

    private final AuditAccessControl control = new AuditAccessControl();

    private AuditUser user(String name, String... roles) {
        return new AuditUser(name, name, Set.of(roles));
    }

    private AuditEvent eventOf(String actor) {
        return new AuditEvent("evt-1", "req-1", 1, actor, "ORDER_CREATE",
                "ORDER", "ORD-1", Map.of(), OperationResult.SUCCESS, null,
                Instant.now(), 0, false);
    }

    private void assertReason(AuditAccessDeniedException ex, AccessDeniedReason reason) {
        assertThat(ex.getReason()).isEqualTo(reason);
    }

    @Test
    @DisplayName("未认证访问：拒绝，原因 UNAUTHENTICATED（401 类）")
    void unauthenticated() {
        assertThatThrownBy(() -> control.checkAuthenticated(null))
                .isInstanceOf(AuditAccessDeniedException.class)
                .satisfies(ex -> assertReason((AuditAccessDeniedException) ex,
                        AccessDeniedReason.UNAUTHENTICATED));
    }

    @Test
    @DisplayName("普通用户不带具体资源条件查询：拒绝，原因 MISSING_QUERY_CRITERIA，而非静默空")
    void userMustSpecifyResource() {
        assertThatThrownBy(() -> control.checkQuery(user("alice", Roles.USER), null, null))
                .isInstanceOf(AuditAccessDeniedException.class)
                .satisfies(ex -> assertReason((AuditAccessDeniedException) ex,
                        AccessDeniedReason.MISSING_QUERY_CRITERIA));
    }

    @Test
    @DisplayName("普通用户限定到自己资源的查询：允许")
    void userQueryOwnResourceAllowed() {
        assertThatCode(() -> control.checkQuery(user("alice", Roles.USER), "ORDER", "ORD-1"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("普通用户读取他人记录：拒绝，原因 NOT_RESOURCE_OWNER")
    void userCannotReadOthers() {
        assertThatThrownBy(() -> control.checkRead(user("bob", Roles.USER), eventOf("alice")))
                .isInstanceOf(AuditAccessDeniedException.class)
                .satisfies(ex -> assertReason((AuditAccessDeniedException) ex,
                        AccessDeniedReason.NOT_RESOURCE_OWNER));
    }

    @Test
    @DisplayName("普通用户读取自己记录：允许")
    void userReadOwnAllowed() {
        assertThatCode(() -> control.checkRead(user("alice", Roles.USER), eventOf("alice")))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("审计员可查询/读取全部，但导出被拒绝，原因 EXPORT_FORBIDDEN")
    void auditorCanReadButNotExport() {
        assertThatCode(() -> control.checkRead(user("auditor", Roles.AUDITOR), eventOf("alice")))
                .doesNotThrowAnyException();
        assertThatCode(() -> control.checkQuery(user("auditor", Roles.AUDITOR), null, null))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> control.checkExport(user("auditor", Roles.AUDITOR)))
                .isInstanceOf(AuditAccessDeniedException.class)
                .satisfies(ex -> assertReason((AuditAccessDeniedException) ex,
                        AccessDeniedReason.EXPORT_FORBIDDEN));
    }

    @Test
    @DisplayName("管理员查询、读取、导出均允许")
    void adminAllAllowed() {
        AuditUser admin = user("root", Roles.ADMIN);
        assertThatCode(() -> control.checkRead(admin, eventOf("alice"))).doesNotThrowAnyException();
        assertThatCode(() -> control.checkExport(admin)).doesNotThrowAnyException();
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.audit.security;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import org.springframework.stereotype.Component;

/**
 * 审计数据的角色化访问控制。
 *
 * <ul>
 *   <li>USER：只能查自己拥有资源的记录，且必须限定到具体资源（resourceType+resourceId）；
 *       访问他人资源明确拒绝（NOT_RESOURCE_OWNER），不是静默空结果。</li>
 *   <li>AUDITOR：可查询/读取全部记录，但不能导出。</li>
 *   <li>ADMIN：查询、读取、导出全部允许。</li>
 * </ul>
 */
@Component
public class AuditAccessControl {

    public void checkAuthenticated(AuditUser user) {
        if (user == null) {
            throw new AuditAccessDeniedException(AccessDeniedReason.UNAUTHENTICATED,
                    "未认证：缺少 " + com.github.feng111627.audittrailcomplianceservicejava.audit.web.UserAuthenticationFilter.USER_HEADER
                            + " 请求头或登录信息");
        }
    }

    public void checkQuery(AuditUser user, String resourceType, String resourceId) {
        checkAuthenticated(user);
        if (hasRole(user, Roles.ADMIN) || hasRole(user, Roles.AUDITOR)) {
            return;
        }
        // 普通用户必须把范围限定到某个具体资源，禁止全量/大范围扫描。
        if (resourceType == null || resourceType.isBlank()
                || resourceId == null || resourceId.isBlank()) {
            throw new AuditAccessDeniedException(AccessDeniedReason.MISSING_QUERY_CRITERIA,
                    "普通用户只能查询自己拥有的具体资源，必须同时提供 resourceType 与 resourceId");
        }
    }

    public void checkRead(AuditUser user, AuditEvent event) {
        checkAuthenticated(user);
        if (hasRole(user, Roles.ADMIN) || hasRole(user, Roles.AUDITOR)) {
            return;
        }
        if (!user.username().equals(event.actor())) {
            throw new AuditAccessDeniedException(AccessDeniedReason.NOT_RESOURCE_OWNER,
                    "拒绝访问：资源 " + event.resourceType() + "/" + event.resourceId()
                            + " 的审计记录不属于当前用户 " + user.username());
        }
    }

    public void checkExport(AuditUser user) {
        checkAuthenticated(user);
        if (hasRole(user, Roles.ADMIN)) {
            return;
        }
        if (hasRole(user, Roles.AUDITOR)) {
            throw new AuditAccessDeniedException(AccessDeniedReason.EXPORT_FORBIDDEN,
                    "审计员只有查询权限，导出仅限 ADMIN 角色");
        }
        throw new AuditAccessDeniedException(AccessDeniedReason.EXPORT_FORBIDDEN,
                "当前角色无权导出审计记录，导出仅限 ADMIN 角色");
    }

    private boolean hasRole(AuditUser user, String role) {
        return user.roles() != null && user.roles().contains(role);
    }
}

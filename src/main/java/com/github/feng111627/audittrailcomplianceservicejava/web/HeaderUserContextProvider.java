package com.github.feng111627.audittrailcomplianceservicejava.web;

import com.github.feng111627.audittrailcomplianceservicejava.audit.UserContext;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 演示用操作人解析：从请求头读取身份信息，便于本地与单测模拟不同角色。
 * <ul>
 *   <li>{@code X-User}：用户名；</li>
 *   <li>{@code X-Roles}：逗号分隔的角色，如 {@code ADMIN,AUDITOR}。</li>
 * </ul>
 * 生产环境应替换为真实认证体系（JWT/Session/Spring Security）。
 * 未提供身份信息时返回 {@code null}（视为未认证用户）。
 */
@Component
public class HeaderUserContextProvider {

    public UserContext currentUser() {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        String username = attrs.getRequest().getHeader("X-User");
        if (username == null || username.isBlank()) {
            return null;
        }
        String rolesHeader = attrs.getRequest().getHeader("X-Roles");
        Set<String> roles = new LinkedHashSet<>();
        if (rolesHeader != null && !rolesHeader.isBlank()) {
            Arrays.stream(rolesHeader.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .forEach(roles::add);
        }
        return new UserContext(username, roles);
    }
}

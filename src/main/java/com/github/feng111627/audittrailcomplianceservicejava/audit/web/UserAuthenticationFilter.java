package com.github.feng111627.audittrailcomplianceservicejava.audit.web;

import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.Roles;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 极简演示鉴权：从 X-User / X-Roles 请求头解析当前调用方写入安全上下文。
 * 真实系统可替换为 JWT/Session 解析，下游接口无感知。
 */
@Component
@Order(2)
public class UserAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_HEADER = "X-User";
    public static final String ROLES_HEADER = "X-Roles";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String username = request.getHeader(USER_HEADER);
        try {
            if (username != null && !username.isBlank()) {
                Set<String> roles = parseRoles(request.getHeader(ROLES_HEADER));
                AuditSecurityContext.set(new AuditUser(username, username, roles));
            }
            filterChain.doFilter(request, response);
        } finally {
            AuditSecurityContext.clear();
        }
    }

    private Set<String> parseRoles(String header) {
        if (header == null || header.isBlank()) {
            return Set.of(Roles.USER);
        }
        return Arrays.stream(header.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toUpperCase)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}

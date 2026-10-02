package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.web.HeaderUserContextProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 为每个 HTTP 请求建立独立的 {@link AuditContext}，请求结束时清理 ThreadLocal。
 *
 * <p>支持请求头：
 * <ul>
 *   <li>{@code X-Trace-Id}：由上游传入则沿用，便于链路串联；否则新建；</li>
 *   <li>{@code Idempotency-Key}：参与审计写入去重，重试不会写出重复记录。</li>
 * </ul>
 * 响应头回写 {@code X-Trace-Id}，方便排查时把问题请求与审计记录对应起来。
 */
public class AuditContextFilter extends OncePerRequestFilter {

    private final HeaderUserContextProvider userProvider;

    public AuditContextFilter(HeaderUserContextProvider userProvider) {
        this.userProvider = userProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String traceId = request.getHeader("X-Trace-Id");
        if (traceId == null || traceId.isBlank()) {
            traceId = UUID.randomUUID().toString();
        }
        String idempotencyKey = request.getHeader("Idempotency-Key");
        UserContext user = userProvider.currentUser();

        AuditContext context = new AuditContext(traceId, UUID.randomUUID().toString(), user, idempotencyKey);
        AuditContextHolder.set(context);
        response.setHeader("X-Trace-Id", traceId);
        try {
            chain.doFilter(request, response);
        } finally {
            // 必须清理：Servlet 容器复用线程，不清理会把上下文串给下一个请求。
            AuditContextHolder.clear();
        }
    }
}

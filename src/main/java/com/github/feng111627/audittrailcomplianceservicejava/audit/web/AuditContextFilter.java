package com.github.feng111627.audittrailcomplianceservicejava.audit.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 为每个请求建立审计上下文：
 * 优先采用客户端传入的 X-Request-Id（便于链路关联与调用方重试幂等），
 * 否则生成一个；无论是否异常都在 finally 清理，杜绝线程复用串请求。
 */
@Component
@Order(1)
public class AuditContextFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_HEADER = "X-Request-Id";

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        // 异步 dispatch 时同一请求线程状态由框架管理，不重复开 scope。
        return true;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestId = request.getHeader(REQUEST_ID_HEADER);
        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
        }
        com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext
                .beginRequest(requestId);
        response.setHeader(REQUEST_ID_HEADER, requestId);
        try {
            filterChain.doFilter(request, response);
        } finally {
            com.github.feng111627.audittrailcomplianceservicejava.audit.context.AuditContext
                    .endRequest();
        }
    }
}

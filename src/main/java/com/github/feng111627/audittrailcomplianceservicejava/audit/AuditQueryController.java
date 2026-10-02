package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.web.HeaderUserContextProvider;
import java.time.Instant;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 审计记录查询/导出接口（JSON 导出）。
 * 鉴权在 service 层完成；请求头 X-User / X-Roles 表示调用方身份。
 */
@RestController
public class AuditQueryController {

    private final AuditQueryService queryService;
    private final HeaderUserContextProvider userProvider;

    public AuditQueryController(AuditQueryService queryService, HeaderUserContextProvider userProvider) {
        this.queryService = queryService;
        this.userProvider = userProvider;
    }

    @GetMapping("/api/audit/events")
    public List<AuditEvent> query(@RequestParam(required = false) String traceId,
                                  @RequestParam(required = false) Instant from,
                                  @RequestParam(required = false) Instant to) {
        UserContext requester = userProvider.currentUser();
        return queryService.query(traceId, from, to, requester);
    }
}

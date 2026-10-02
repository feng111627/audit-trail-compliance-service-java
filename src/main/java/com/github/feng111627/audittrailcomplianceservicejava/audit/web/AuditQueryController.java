package com.github.feng111627.audittrailcomplianceservicejava.audit.web;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditPage;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.AuditService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 审计记录查询与导出接口，受角色访问控制保护。 */
@RestController
@RequestMapping("/api/audit/events")
public class AuditQueryController {

    private final AuditService auditService;

    public AuditQueryController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping
    public AuditPage query(@RequestParam(required = false) String requestId,
                           @RequestParam(required = false) String actor,
                           @RequestParam(required = false) String action,
                           @RequestParam(required = false) String resourceType,
                           @RequestParam(required = false) String resourceId,
                           @RequestParam(defaultValue = "50") int limit,
                           @RequestParam(defaultValue = "0") long offset) {
        return auditService.query(AuditSecurityContext.get(), requestId, actor, action,
                resourceType, resourceId, limit, offset);
    }

    @GetMapping("/{eventId}")
    public AuditEvent get(@PathVariable String eventId) {
        return auditService.get(AuditSecurityContext.get(), eventId);
    }

    @GetMapping("/export")
    public AuditPage export(@RequestParam(defaultValue = "100") int limit) {
        return auditService.export(AuditSecurityContext.get(), limit);
    }
}

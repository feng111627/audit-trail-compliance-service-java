package com.github.feng111627.audittrailcomplianceservicejava.audit.web;

import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityReport;
import com.github.feng111627.audittrailcomplianceservicejava.audit.integrity.IntegrityVerificationService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessControl;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import java.time.Instant;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 完整性校验入口：按时间范围对哈希链做一次校验，仅限 AUDITOR/ADMIN。 */
@RestController
@RequestMapping("/api/audit/integrity")
public class IntegrityController {

    private final IntegrityVerificationService verificationService;
    private final AuditAccessControl accessControl;

    public IntegrityController(IntegrityVerificationService verificationService,
                               AuditAccessControl accessControl) {
        this.verificationService = verificationService;
        this.accessControl = accessControl;
    }

    /**
     * 校验落库时间在 [from, to] 的记录（ISO-8601，省略表示不限）。
     * 返回整体是否完整、覆盖量与第一处异常位置。
     */
    @GetMapping("/verify")
    public IntegrityReport verify(
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        accessControl.checkIntegrityVerify(AuditSecurityContext.get());
        return verificationService.verify(from, to);
    }
}

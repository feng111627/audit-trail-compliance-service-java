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

/**
 * 完整性校验入口：按时间范围（from/to，ISO-8601）或链上序号范围
 * （fromIndex/toIndex）跑一次校验，返回整体是否完整、覆盖记录数与第一处异常位置。
 * 仅 AUDITOR / ADMIN 可调用。
 */
@RestController
@RequestMapping("/api/audit/integrity")
public class AuditIntegrityController {

    private final IntegrityVerificationService verificationService;
    private final AuditAccessControl accessControl;

    public AuditIntegrityController(IntegrityVerificationService verificationService,
                                    AuditAccessControl accessControl) {
        this.verificationService = verificationService;
        this.accessControl = accessControl;
    }

    @GetMapping("/verify")
    public IntegrityReport verify(
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) Long fromIndex,
            @RequestParam(required = false) Long toIndex) {
        accessControl.checkIntegrityVerify(AuditSecurityContext.get());
        return verificationService.verify(from, to, fromIndex, toIndex);
    }
}

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
 * 完整性校验入口，仅限 AUDITOR/ADMIN。
 * 支持两种范围：按落库时间（from/to）或按链上位置区间（fromPosition/toPosition），
 * 两者都省略时校验全量；同时给出时以位置区间为准。
 */
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
     * 校验落库时间在 [from, to]（ISO-8601，省略表示不限）的记录。
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

    /**
     * 校验链上位置在 [fromPosition, toPosition]（闭区间，toPosition 省略表示到链尾）的环节。
     * 衔接校验会回查区间外的前驱环，区间起点处的断链也能检出。
     */
    @GetMapping("/verify-range")
    public IntegrityReport verifyRange(
            @RequestParam long fromPosition,
            @RequestParam(required = false) Long toPosition) {
        accessControl.checkIntegrityVerify(AuditSecurityContext.get());
        return verificationService.verifyRange(fromPosition, toPosition);
    }
}

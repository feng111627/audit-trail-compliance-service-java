package com.github.feng111627.audittrailcomplianceservicejava.audit.web;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AccessDeniedReason;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditAccessDeniedException;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.AuditService;
import com.github.feng111627.audittrailcomplianceservicejava.demo.BusinessException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 把拒绝/异常翻译成带可区分原因的 HTTP 响应，同时保证“校验未过也被留痕”。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final AuditService auditService;

    public GlobalExceptionHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    /** 参数校验未通过：请求体校验发生在进入业务方法之前，切面拦不到，这里补留痕。 */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }
        recordValidationRejected(ex, fieldErrors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "result", OperationResult.VALIDATION_REJECTED.name(),
                "reason", "参数校验未通过",
                "fieldErrors", fieldErrors));
    }

    private void recordValidationRejected(MethodArgumentNotValidException ex,
                                          Map<String, String> fieldErrors) {
        AuditUser user = AuditSecurityContext.get();
        String actor = user == null ? "anonymous" : user.username();
        try {
            auditService.record(actor, "HTTP_REQUEST_VALIDATION", "HTTP_REQUEST",
                    requestPath(), Map.of("fieldErrors", fieldErrors),
                    OperationResult.VALIDATION_REJECTED,
                    "[校验拒绝] " + fieldErrors);
        } catch (Exception ignored) {
            // 校验留痕失败不改变原有响应
        }
    }

    private String requestPath() {
        try {
            var attrs = org.springframework.web.context.request.RequestContextHolder
                    .getRequestAttributes();
            if (attrs instanceof org.springframework.web.context.request.ServletRequestAttributes sra) {
                return sra.getRequest().getRequestURI();
            }
        } catch (Exception ignored) {
            // 非 web 环境
        }
        return null;
    }

    /** 业务规则拒绝。 */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Map<String, Object>> handleBusiness(BusinessException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "result", OperationResult.FAILED.name(),
                "reason", ex.getMessage()));
    }

    /** 越权访问：明确拒绝并给出可区分原因，而不是静默空结果。 */
    @ExceptionHandler(AuditAccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleDenied(AuditAccessDeniedException ex) {
        HttpStatus status = ex.getReason() == AccessDeniedReason.UNAUTHENTICATED
                ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN;
        return ResponseEntity.status(status).body(Map.of(
                "denied", true,
                "reason", ex.getReason().name(),
                "message", ex.getMessage()));
    }

    /** 参数非法（如校验区间 fromPosition/toPosition 不合法）：明确 400。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "result", OperationResult.FAILED.name(),
                "reason", ex.getMessage()));
    }

    /** 未预期异常：系统中断。 */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "result", OperationResult.ERROR.name(),
                "reason", "系统内部错误: " + ex.getClass().getSimpleName()));
    }
}

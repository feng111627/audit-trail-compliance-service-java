package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 把各类失败映射为带明确 reasonCode/message 的 HTTP 响应。
 * 越权与校验失败绝不表现为“静默空结果”。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body(
                "ACCESS_DENIED_" + ex.reason().name(), ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body(
                "VALIDATION_REJECTED", ex.getMessage()));
    }

    @ExceptionHandler(BusinessFailureException.class)
    public ResponseEntity<Map<String, Object>> handleBusiness(BusinessFailureException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body(
                "BUSINESS_FAILURE", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body(
                "ERROR:" + ex.getClass().getSimpleName(), ex.getMessage()));
    }

    private Map<String, Object> body(String reasonCode, String message) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("reasonCode", reasonCode);
        map.put("message", message);
        return map;
    }
}

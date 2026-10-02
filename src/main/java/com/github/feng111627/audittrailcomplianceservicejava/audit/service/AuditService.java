package com.github.feng111627.audittrailcomplianceservicejava.audit.service;

import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditEvent;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.AuditPage;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import java.util.Map;

/** 审计留痕入口。 */
public interface AuditService {

    AuditEvent record(String actor, String action, String resourceType, String resourceId,
                      Map<String, Object> parameters, OperationResult result, String reason);

    /** 带耗时的留痕，供切面在方法返回后补记耗时。 */
    AuditEvent record(String actor, String action, String resourceType, String resourceId,
                      Map<String, Object> parameters, OperationResult result, String reason,
                      long durationMillis);

    AuditPage query(AuditUser user, String requestId, String actor, String action,
                    String resourceType, String resourceId, int limit, long offset);

    AuditEvent get(AuditUser user, String eventId);

    AuditPage export(AuditUser user, int limit);

    long purgeExpired();
}

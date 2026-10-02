package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 审计能力配置：开关、留存天数、清理 cron、允许查询审计数据的角色。 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    private boolean enabled = true;
    private int retentionDays = 90;
    private String purgeCron = "0 0 2 * * ?";
    private List<String> queryRoles = List.of("AUDITOR", "ADMIN");

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public int getRetentionDays() { return retentionDays; }
    public void setRetentionDays(int retentionDays) { this.retentionDays = retentionDays; }
    public String getPurgeCron() { return purgeCron; }
    public void setPurgeCron(String purgeCron) { this.purgeCron = purgeCron; }
    public List<String> getQueryRoles() { return queryRoles; }
    public void setQueryRoles(List<String> queryRoles) { this.queryRoles = queryRoles; }
}

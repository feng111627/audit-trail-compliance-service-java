package com.github.feng111627.audittrailcomplianceservicejava.audit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 审计配置：留存天数、清理方式与定时任务。 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    private boolean enabled = true;
    private final Retention retention = new Retention();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Retention getRetention() {
        return retention;
    }

    public static class Retention {
        /** 留存天数，超过即按 purgeMode 处理。 */
        private int days = 90;
        /** DELETE：物理删除；ANONYMIZE：匿名化保留。 */
        private String purgeMode = "DELETE";
        private String cron = "0 30 2 * * *";
        private boolean purgeOnStartup = false;

        public int getDays() { return days; }
        public void setDays(int days) { this.days = days; }
        public String getPurgeMode() { return purgeMode; }
        public void setPurgeMode(String purgeMode) { this.purgeMode = purgeMode; }
        public String getCron() { return cron; }
        public void setCron(String cron) { this.cron = cron; }
        public boolean isPurgeOnStartup() { return purgeOnStartup; }
        public void setPurgeOnStartup(boolean purgeOnStartup) { this.purgeOnStartup = purgeOnStartup; }
    }
}

package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

/** 完整性校验发现的异常类型。 */
public enum AnomalyType {
    /** 记录内容与落库时的哈希对不上（内容被改动）。 */
    CONTENT_TAMPERED,
    /** 记录的 previousHash 与前序记录/墓碑的哈希对不上（链被断开或重排）。 */
    CHAIN_LINK_BROKEN,
    /** 链上序号缺失且没有正常清理的墓碑（记录被人为删除）。 */
    RECORD_MISSING,
    /** 匿名化哈希存在但记录并不像正常匿名化产物（借匿名化掩盖篡改）。 */
    ANONYMIZATION_INVALID
}

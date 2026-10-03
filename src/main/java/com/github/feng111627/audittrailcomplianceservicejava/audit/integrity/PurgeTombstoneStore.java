package com.github.feng111627.audittrailcomplianceservicejava.audit.integrity;

import java.util.Optional;

/**
 * 留存清理“墓碑”存储：记录被正常清理（物理删除）的链上记录的
 * chainIndex -> eventHash 映射。校验时遇到链上缺口，若缺口处有墓碑且
 * 后序记录的 previousHash 与墓碑哈希吻合，则判定为正常清理而非篡改。
 *
 * <p>墓碑只含序号与哈希，不含业务内容，体量极小；生产可替换为数据库表实现。
 */
public interface PurgeTombstoneStore {

    /** 为一条被正常清理的链上记录登记墓碑。 */
    void put(long chainIndex, String eventHash);

    /** 查询某个链上序号是否有正常清理的墓碑。 */
    Optional<String> findHash(long chainIndex);

    long count();
}

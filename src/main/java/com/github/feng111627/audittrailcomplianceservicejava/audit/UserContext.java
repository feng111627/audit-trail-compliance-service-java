package com.github.feng111627.audittrailcomplianceservicejava.audit;

import java.util.Set;

/** 当前操作人上下文：用户名与角色集合。 */
public record UserContext(String username, Set<String> roles) {
}

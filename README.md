# audit-trail-compliance-service-java

基于 Spring Boot 3.4 的审计留痕能力：对关键业务操作自动记录“谁、什么时间、对什么资源、
做了什么、结果如何”，并覆盖失败/拒绝/异常、并发与异步归属、敏感数据脱敏、按角色查询鉴权、
留存与过期清理。

快速开始与本地验证见 [`docs/AUDIT_TRAIL.md`](docs/AUDIT_TRAIL.md)。

## 运行

```bash
mvn spring-boot:run          # 启动（随机端口，日志可见实际端口）
mvn test                     # 运行全部测试，控制台按业务点打印用例通过情况
```

## 能力一览

- **自动留痕**：在业务方法上加 `@Audited(action=..., resourceType=..., resourceIdExpr=...)`，
  成功、业务失败、参数校验拒绝、越权拒绝、异常中断都会留痕，且异常照常抛出。
- **请求归属与先后**：每个请求一个 `traceId`（可由 `X-Trace-Id` 头传入），操作间用
  `spanId/parentSpanId` 表达嵌套，同 trace 内用单调递增 `seq` 表达先后。
- **并发与异步**：`ThreadLocal` 上下文 + 异步任务装饰器透传，跨线程不串请求；
  `Idempotency-Key` + action 构成幂等键，并发/重试不写重。
- **脱敏**：手机号、证件号按模式扫描脱敏；密码/密钥类字段整体打码。落库前、查询返回前两道处理。
- **查询鉴权**：`GET /api/audit/events` 按角色控制；未认证与角色越权返回不同的明确原因，
  绝不静默返回空结果。
- **留存清理**：`audit.retention-days` 配置留存天数，`audit.purge-cron` 配置清理时机，
  过期数据物理删除（可扩展为归档）。

演示接口（自动留痕，无需手写记录代码）：

| 接口 | 演示的审计结果 |
| --- | --- |
| `POST /api/demo/orders` | SUCCESS / VALIDATION_REJECTED / FAILURE(黑名单) |
| `POST /api/demo/orders/{id}/cancel` | SUCCESS / FAILURE(已完结) |
| `POST /api/demo/orders/{id}/approve` | ACCESS_DENIED / SUCCESS（需 ADMIN） |
| `POST /api/demo/orders/{id}/risk` | ERROR（异常中断） |
| `POST /api/demo/orders/{id}/async` | @Async 异步留痕（上下文透传） |
| `GET /api/audit/events` | 审计查询/导出（需 AUDITOR/ADMIN） |

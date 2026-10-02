# 审计留痕能力说明

## 1. 记录了哪些事件

所有标注了 `@Audited` 的方法，无论成功还是抛出异常，都会产生一条审计记录
（`AuditEvent`），字段含义如下：

| 字段 | 含义 |
| --- | --- |
| `eventId` | 记录全局唯一 ID（UUID） |
| `traceId` | 请求链路 ID；同一次请求内多个操作共享，可由请求头 `X-Trace-Id` 传入，响应头回写 |
| `spanId` / `parentSpanId` | 操作的嵌套关系：内层操作的 parentSpanId 指向直接外层 |
| `seq` | 同一 trace 内单调递增序号，在事件落库（操作完成）时分配，表示完成先后 |
| `eventTime` | 事件时间（UTC） |
| `actor` / `actorRoles` | 操作人及其角色（演示实现从 `X-User`/`X-Roles` 请求头读取） |
| `action` / `resourceType` / `resourceId` | 动作、资源类型、资源标识（SpEL 表达式，如 `#request.orderId()`） |
| `outcome` + `reasonCode` | 结果分类与原因码（见下表） |
| `reasonDetail` | 失败/拒绝的原因描述（落库前脱敏） |
| `params` | 入参摘要（落库前脱敏）；可通过 `recordParams=false` 关闭 |
| `durationMs` | 方法耗时 |
| `threadName` | 执行线程名，可区分主请求线程与异步线程 |
| `idempotencyKey` | 幂等键（请求头 `Idempotency-Key`） |

### 结果分类（明确区分“被拒绝”与“被中断”）

| outcome | 触发条件 | reasonCode 示例 | HTTP |
| --- | --- | --- | --- |
| `SUCCESS` | 方法正常返回 | `OK` | 200 |
| `VALIDATION_REJECTED` | `IllegalArgumentException` 等参数校验失败——**操作被拒绝** | `VALIDATION_REJECTED` | 400 |
| `FAILURE` | `BusinessFailureException`，业务规则不允许——**操作被拒绝** | `BUSINESS_FAILURE` | 409 |
| `ACCESS_DENIED` | 未认证或角色不足——**操作被拒绝** | `ACCESS_DENIED_NOT_AUTHENTICATED` / `ACCESS_DENIED_FORBIDDEN_ROLE` | 403 |
| `ERROR` | 其他未预期异常——**操作被中断** | `ERROR:<异常类型>`，如 `ERROR:IllegalStateException` | 500 |

失败、校验不过、异常中断的操作都不会被悄悄丢掉：异常原样向上抛出，但审计记录一定落库。

### 一次请求中的多个操作、并发与异步

- HTTP 请求进入时由 `AuditContextFilter` 建立独立上下文，请求结束在 `finally` 中清理，
  线程复用不会串请求。
- 嵌套调用：进入 `@Audited` 方法压入 span，退出弹出；内层记录的 `parentSpanId`
  指向外层 `spanId`。
- 并发：每个线程绑定自己的上下文；16 线程并发的单测验证了记录只归属各自 traceId。
- 异步（`@Async`）：`AuditTaskDecorator` 在任务提交时复制上下文快照，
  在工作线程恢复（共享 traceId/操作人/幂等键，独立 span 栈与 seq），执行完清理。
- **不写重**：仓储以 `idempotencyKey + action` 为唯一键做原子 putIfAbsent；
  同一 `Idempotency-Key` 下并发执行或 HTTP 重试，同一动作只保留一条。
  无幂等键时以全局唯一 `eventId` 兜底。

## 2. 脱敏规则

组件：`SensitiveDataMasker`。在两处执行，双保险：

1. **落库前**：切面拼装入参、记录异常消息时；
2. **对外查询/导出前**：`AuditQueryService` 对返回结果再处理一次。

| 敏感类型 | 规则 | 示例 |
| --- | --- | --- |
| 手机号（大陆 11 位） | 保留前 3 后 4，中间 4 位 `*` | `13812348000` → `138****8000` |
| 身份证号（18 位） | 保留前 6 后 4，中间 8 位 `*` | `11010119900307123X` → `110101********123X` |
| 身份证号（15 位） | 保留前 6 后 4，中间 5 位 `*` | `110101199001011234` → `110101*****1234` |
| 密码/密钥类字段 | 值整体替换为 `******` | `password=SuperSecret` → `password=******` |

密码类字段按**字段名**识别（大小写不敏感，包含 `password/passwd/pwd/secret/token/密码/口令`），
兼容 `key=value` 与 JSON 的 `"key":"value"` 写法；手机号、证件号按**内容模式**在任意文本中扫描
（JSON、record 的 toString、异常消息、自由文本）。证件号正则先于手机号执行，
避免长号码被局部规则提前处理。

## 3. 查询/导出鉴权

- 接口：`GET /api/audit/events?traceId=&from=&to=`（from/to 为 ISO-8601 时间）。
- 允许角色由 `audit.query-roles` 配置，默认 `AUDITOR,ADMIN`。
- 越权行为**明确拒绝**（HTTP 403 + JSON body），两种原因可区分：
  - 未提供身份：`{"reasonCode":"ACCESS_DENIED_NOT_AUTHENTICATED", ...}`
  - 已登录但角色不足：`{"reasonCode":"ACCESS_DENIED_FORBIDDEN_ROLE", ...}`（消息含用户名）

## 4. 留存时长与过期数据处理

`application.properties`：

```properties
audit.enabled=true            # 总开关
audit.retention-days=90       # 留存天数；<=0 表示永久留存（不做删除）
audit.purge-cron=0 0 2 * * ?  # 每天 02:00 清理（cron 6 段）
audit.query-roles=AUDITOR,ADMIN
```

- 过期数据处理方式：**物理删除** `eventTime < now - retentionDays` 的记录，
  由 `RetentionService` 定时执行，日志输出删除条数。
- 需要“删除前归档”时，在 `RetentionService.purgeExpiredOnce()` 删除动作前扩展归档步骤即可。
- 当前存储实现是内存版（`InMemoryAuditEventRepository`，并发安全、幂等写入），
  生产可替换为数据库实现，并对 `(idempotency_key, action)` 建唯一索引。

## 5. 如何在本地验证

启动服务：

```bash
mvn spring-boot:run
```

另开终端（端口默认随机；也可在命令中加 `-Dserver.port=8080`）：

```bash
# 1) 正常下单 → 200，响应头拿到 X-Trace-Id；审计为 SUCCESS，敏感字段已脱敏
curl -i -X POST http://localhost:8080/api/demo/orders \
  -H 'Content-Type: application/json' -H 'X-User: alice' -H 'X-Roles: USER' \
  -d '{"orderId":"O-1","customerName":"张三","phone":"13812348000","idCard":"11010119900307123X"}'

# 2) 参数校验失败 → 400 VALIDATION_REJECTED；黑名单订单 → 409 BUSINESS_FAILURE；
#    /risk → 500 ERROR:IllegalStateException；/approve 用普通用户 → 403
curl -i -X POST http://localhost:8080/api/demo/orders/O-7/risk -H 'X-User: alice'
curl -i -X POST http://localhost:8080/api/demo/orders/O-1/approve -H 'X-User: bob' -H 'X-Roles: USER'

# 3) 重试幂等：同样的 Idempotency-Key 调两次，审计只写一条
for i in 1 2; do curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/api/demo/orders \
  -H 'X-User: alice' -H 'Idempotency-Key: k-1' -H 'Content-Type: application/json' -d '{"orderId":"X"}'; done

# 4) 未认证查询 → 403 + ACCESS_DENIED_NOT_AUTHENTICATED
curl -i http://localhost:8080/api/audit/events
#    普通角色 → 403 + ACCESS_DENIED_FORBIDDEN_ROLE
curl -i http://localhost:8080/api/audit/events -H 'X-User: bob' -H 'X-Roles: USER'
#    审计员查询 → 200，返回记录中手机号为 138****8000
curl -s 'http://localhost:8080/api/audit/events?traceId=<上一步的X-Trace-Id>' \
  -H 'X-User: auditor1' -H 'X-Roles: AUDITOR'

# 5) 异步操作：审计记录与原请求同 traceId，线程名 audit-async-*
curl -i -X POST http://localhost:8080/api/demo/orders/O-9/async -H 'X-User: alice'
```

### 运行测试

```bash
mvn test
```

控制台会按业务点分组打印每个用例的名称与“通过 ✓/失败 ✗”。测试与业务点对应关系：

| 测试类 | 覆盖的业务点 |
| --- | --- |
| `SensitiveDataMaskerTest` | 手机号/证件号/密码三类脱敏，含文本混合与防误伤 |
| `AuditTrailOutcomeTest` | 成功留痕；校验拒绝、业务失败、异常中断不丢失；嵌套操作归属与先后 |
| `AuditConcurrencyAsyncTest` | 16 线程并发 trace 隔离；幂等键去重与不误伤；@Async 上下文透传；异步内失败留痕 |
| `AuditAccessControlTest` | 未认证/越权两种可区分原因；角色可配置；输出兜底脱敏；trace 过滤；留存清理 |
| `AuditHttpIntegrationTest` | 过滤器→切面→查询接口的 HTTP 全链路、状态码与原因码、幂等头 |

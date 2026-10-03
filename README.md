# 审计留痕合规服务（Audit Trail & Compliance）

在 Spring Boot 工程上增加的一套“关键操作自动留痕”能力：谁、在什么时间、对什么资源、做了什么、结果如何都可查；失败、校验未过、异常中断都不会被悄悄丢掉；支持并发/异步归属、敏感数据脱敏、角色化查询与导出、可配置留存。

## 1. 记录了哪些事件

在业务方法上标注 `@Audited` 即自动留痕（见 `demo/DemoOrderService`）：

| 动作 action | 触发位置 | 说明 |
|---|---|---|
| `ORDER_CREATE` | 创建订单 | resourceId 取返回值 `#result.id()`；同时触发异步 `ORDER_NOTIFY_SENT` |
| `ORDER_UPDATE_PHONE` | 修改手机号 | 记录新手机号（脱敏后） |
| `ORDER_CANCEL` | 取消订单 | 操作他人订单会被业务拒绝 |
| `ORDER_QUERY` | 查询订单 | |
| `ORDER_TRIGGER_ERROR` | 演示异常 | 抛出系统异常，验证异常中断留痕 |
| `ORDER_ASYNC_NOTIFY` / `ORDER_NOTIFY_SENT` | 异步通知 | 验证跨线程上下文归属，异步记录 `async=true` |
| `HTTP_REQUEST_VALIDATION` | `@Valid` 校验失败 | 在进入业务方法前被拒，由全局异常处理器补记 |

每条记录（`AuditEvent`）包含：

- `eventId`：由 `requestId + 请求内序列号` 确定性生成，天然幂等；
- `requestId`：一次请求的归属标识，取请求头 `X-Request-Id`，未传则自动生成并在响应头返回；
- `sequence`：同一请求内单调递增，用于还原先后顺序；
- `actor`（操作人）、`action`（动作）、`resourceType/resourceId`（资源）；
- `parameters`：入参（**脱敏后**）；
- `result`：`SUCCESS` / `FAILED`（业务被拒绝）/ `VALIDATION_REJECTED`（参数校验未过）/ `ERROR`（异常中断）；
- `reason`：带前缀的原因，如 `[业务拒绝]`、`[校验拒绝]`、`[异常中断]`；
- `timestamp`、`durationMillis`、`async`。

### 成功、失败、异常都留痕

`AuditAspect` 对 `@Audited` 方法做环绕：
- 正常返回 → `SUCCESS`；
- 抛 `BusinessException` → `FAILED`（被拒绝，原因可见）；
- 抛 Bean Validation 异常 → `VALIDATION_REJECTED`；
- 其它异常 → `ERROR`（被中断），留痕后异常照常抛出。

请求体 `@Valid` 失败发生在进入方法之前，切面拦不到，由 `GlobalExceptionHandler` 补一条 `VALIDATION_REJECTED`。

## 2. 并发、重试与异步

- 每个请求由 `AuditContextFilter` 建立 `AuditContext`（ThreadLocal），结束时一定清理，线程复用不会串请求。
- 请求内的序列号由共享的 `AtomicLong` 产生，多线程并发也不重复、可排序。
- 异步：`auditExecutor` 线程池配置了 `TaskDecorator`，在提交时抓取 `requestId`/序列号计数器与当前用户快照，在工作线程恢复，异步记录仍归属原请求；也可手动用 `AuditContext.wrap(...)` 包装任务。
- 防重写：仓储 `saveIfAbsent` 基于唯一 `eventId`，同一次操作即使调用侧重试也只落库一次。

## 3. 脱敏规则

由 `DefaultMaskingService` 在**落库前**统一处理，查询出口同样只持有脱敏后的数据：

| 类型 | 规则 | 示例 |
|---|---|---|
| 密码/密钥（`@Sensitive(PASSWORD)` 或参数名含 password/secret） | 统一 `******`，不暴露长度 | `supersecret` → `******` |
| 手机号（`PHONE` / 名字含 phone/mobile） | 保留前 3 后 4 | `13812341234` → `138****1234` |
| 证件号（`ID_CARD` / 名字含 idCard/certNo） | 保留前 6 后 4 | `110101199003078888` → `110101********8888` |

支持对 record / 普通 bean / 集合 / 数组 / Map 递归脱敏（字段上的 `@Sensitive` 注解优先，参数名兜底）。

## 4. 查询 / 导出的角色控制

请求头 `X-User` 指定用户、`X-Roles` 指定角色（逗号分隔；演示用，生产替换为 JWT/Session）。

| 角色 | 查询/读取范围 | 导出 |
|---|---|---|
| `USER` | 只能查**自己拥有的具体资源**，必须同时给 `resourceType` 和 `resourceId`；读他人记录被拒 | 禁止 |
| `AUDITOR` | 可查询、读取全部 | 禁止 |
| `ADMIN` | 全部 | 允许 |

越权一律**明确拒绝并给出可区分原因**，不是静默返回空：

- `UNAUTHENTICATED` → HTTP 401（未登录）
- `MISSING_QUERY_CRITERIA` → 403（普通用户未限定到具体资源）
- `NOT_RESOURCE_OWNER` → 403（访问他人资源的记录）
- `EXPORT_FORBIDDEN` → 403（无导出权限）

接口：

- `GET /api/audit/events`：条件查询（requestId/actor/action/resourceType/resourceId + limit/offset）
- `GET /api/audit/events/{eventId}`：读取单条
- `GET /api/audit/events/export`：导出（仅 ADMIN）

## 5. 留存时长与过期处理

`application.properties`：

```properties
audit.retention.days=90              # 留存天数
audit.retention.purge-mode=DELETE    # DELETE 物理删除 / ANONYMIZE 匿名化保留
audit.retention.cron=0 30 2 * * *    # 每天 02:30 执行
audit.retention.purge-on-startup=false
```

- `DELETE`：超过留存天数的记录物理删除；
- `ANONYMIZE`：记录骨架（动作、资源、时间、结果）保留，`actor` 置为 `deleted@retention`、参数清空，兼顾可追溯与隐私。

定时任务见 `RetentionService`。当前仓储为内存实现（`InMemoryAuditEventRepository`），生产可实现 `AuditEventRepository` 替换为 JPA/ES，并在 `event_id` 上建唯一索引承接幂等语义。

## 6. 防篡改链与完整性校验

光“记下来”还不够，这层能力让记录**事后被改动可被发现、可定位**。

### 6.1 怎么定义的

每条新记录落库前由 `HashChainService` 接入一条哈希链（`audit/integrity/`）：

- `chainIndex`：链内序号，从 0 开始严格递增；
- `previousHash`：前一条入链记录的 `eventHash`，链首为常量 `GENESIS`；
- `eventHash`：`SHA-256(规范化内容 + previousHash)`，写入后**不再变化**（匿名化也不改）；
- `anonymizedHash`：留存匿名化后按新内容重算的哈希（未匿名化为 `null`）。

因为每条都“咬住”前一条，任何人事后绕过接口直接改库/删库，都会在校验时暴露：

| 异常类型 | 含义 |
|---|---|
| `CONTENT_TAMPERED` | 记录内容与落库时的哈希对不上（内容被改） |
| `CHAIN_LINK_BROKEN` | `previousHash` 与前序记录对不上（链被断开/重排） |
| `RECORD_MISSING` | 链上序号缺失且无正常清理墓碑（记录被人为删除，含链尾被截断） |
| `ANONYMIZATION_INVALID` | 带匿名化哈希但内容不像正常匿名化产物（借匿名化掩盖篡改） |

### 6.2 校验入口

```
GET /api/audit/integrity/verify?from=...&to=...&fromIndex=...&toIndex=...
```

- 时间范围 `from`/`to`（ISO-8601）或链上序号范围 `fromIndex`/`toIndex`，都不传则校验整条链；
- 仅 `AUDITOR` / `ADMIN` 可调用；
- 返回 `IntegrityReport`：`intact`（整体是否完整）、`scannedCount`/`chainedCount`（本次覆盖记录数）、`legacyCount`/`purgedCount`/`anonymizedCount`（统计），以及**第一处异常**的 `anomalyType` / `anomalyChainIndex` / `anomalyEventId` / `anomalyMessage`——不是只丢一句“校验失败”。

实现上（`IntegrityVerificationService`）：按链序**分批流式**扫描（每批 200 条），内存中只持有一批，数据量大也跑得动；校验只读快照、逐条重算比对，**不加写锁**，不阻塞正常留痕写入。写入侧只在“算哈希 + 幂等落库”的极短临界区内持锁，不拖慢线上写路径。

### 6.3 对历史记录与正常清理的兼容

- **历史遗留**：上线前已存在的记录没有链字段（`chainIndex=-1`、哈希为 `null`），校验时只统计为 `legacyCount`，**不算篡改**；新记录从 `chainIndex=0` 另起新链。
- **正常清理（DELETE）**：`purgeExpired` 物理删除入链记录前，先登记“墓碑”（`chainIndex -> eventHash`，见 `PurgeTombstoneStore`）。校验遇到链上缺口时，有墓碑且哈希吻合 → 计为 `purgedCount`；无墓碑 → 报 `RECORD_MISSING`。“正常清理”与“被人为删除”由此区分。
- **正常清理（ANONYMIZE）**：匿名化后按新内容重算 `anonymizedHash` 回写，`eventHash` 不动，链关联保持完整；校验对匿名化记录比对 `anonymizedHash`，并要求内容确实呈匿名化形态。
- **并发与重试**：链尾推进与幂等落库在同一短锁内完成，多线程并发序号不重不漏；同一 `requestId` 重试产生相同 `eventId`，`saveIfAbsent` 兜底只落一条、链不重复推进。

### 6.4 本地验证

```bash
# 跑全部测试（含防篡改链 10 个用例 + 校验入口权限 4 个用例）
mvn test

# 只看防篡改相关用例
mvn test -Dtest=HashChainIntegrityTest
```

手工验证（先 `mvn spring-boot:run`，另开终端）：

```bash
# 1) 产生几条留痕
curl -s -X POST http://localhost:$PORT/api/orders \
  -H 'Content-Type: application/json' -H 'X-User: alice' -H 'X-Roles: USER' \
  -d '{"owner":"alice","product":"book","phone":"13812341234","payPassword":"paypass"}'

# 2) 审计员跑全链校验 -> intact=true，含覆盖统计
curl -s http://localhost:$PORT/api/audit/integrity/verify \
  -H 'X-User: auditor' -H 'X-Roles: AUDITOR'

# 3) 普通用户调用 -> 403
curl -s http://localhost:$PORT/api/audit/integrity/verify \
  -H 'X-User: bob' -H 'X-Roles: USER'

# 4) 按链上序号范围校验
curl -s 'http://localhost:$PORT/api/audit/integrity/verify?fromIndex=0&toIndex=2' \
  -H 'X-User: root' -H 'X-Roles: ADMIN'
```

篡改/删除的检出效果由自动化用例覆盖（`HashChainIntegrityTest` 中用仓储的 `unsafeReplace`/`unsafeDelete` 测试钩子模拟绕过接口直接改库/删库）。

## 7. 本地验证

### 运行测试（推荐）

```bash
mvn test
```

控制台会按“业务点”打印每个用例的通过情况，覆盖：正常留痕、失败与异常、并发与异步归属、脱敏、越权、留存策略、防篡改链与完整性校验（共 41 个用例）。

### 启动服务手工验证

```bash
mvn spring-boot:run
```

另开终端（服务端口见启动日志；下文以 $PORT 表示）：

```bash
# 1) 正常创建（观察返回头 X-Request-Id；手机号/密码落库即脱敏）
curl -s -X POST http://localhost:$PORT/api/orders \
  -H 'Content-Type: application/json' -H 'X-User: alice' -H 'X-Roles: USER' \
  -d '{"owner":"alice","product":"book","phone":"13812341234","payPassword":"paypass"}' -i

# 2) 校验未过也会留痕（手机号不合法 -> 400 VALIDATION_REJECTED）
curl -s -X POST http://localhost:$PORT/api/orders \
  -H 'Content-Type: application/json' -H 'X-User: alice' \
  -d '{"owner":"alice","product":"book","phone":"123","payPassword":"123456"}'

# 3) 越权：普通用户不带资源条件查询 -> 403 MISSING_QUERY_CRITERIA
curl -s http://localhost:$PORT/api/audit/events -H 'X-User: bob' -H 'X-Roles: USER'

# 4) 审计员导出 -> 403 EXPORT_FORBIDDEN
curl -s http://localhost:$PORT/api/audit/events/export -H 'X-User: auditor' -H 'X-Roles: AUDITOR'

# 5) 管理员导出 -> 200，可看到脱敏后的参数
curl -s http://localhost:$PORT/api/audit/events/export -H 'X-User: root' -H 'X-Roles: ADMIN'
```

## 8. 代码结构

```
audit/
  annotation/   @Audited、@Sensitive
  aspect/       AuditAspect（自动留痕、结果归类）
  context/      AuditContext（requestId/序列号，异步快照传播）
  masking/      脱敏服务
  security/     角色、访问控制、可区分拒绝原因
  repository/   审计仓储接口与内存实现（幂等、查询、过期处理、链式读取）
  integrity/    防篡改哈希链、清理墓碑、完整性校验与报告
  service/      留痕服务、留存清理、哈希计算
  web/          上下文/鉴权过滤器、审计查询接口、完整性校验入口、全局异常处理
  config/       配置属性、异步线程池、定时开关
demo/           订单业务（@Audited 使用示例）与 HTTP 入口
```

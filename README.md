# 审计留痕合规服务（Audit Trail & Compliance）

在 Spring Boot 工程上增加的一套“关键操作自动留痕”能力：谁、在什么时间、对什么资源、做了什么、结果如何都可查；失败、校验未过、异常中断都不会被悄悄丢掉；支持并发/异步归属、敏感数据脱敏、角色化查询与导出、可配置留存；并在此之上提供**防篡改哈希链与完整性校验**，能证明记录落库后没被动过手脚。

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
- `GET /api/audit/integrity/verify`：按时间范围完整性校验（仅 AUDITOR/ADMIN，见第 6 节）
- `GET /api/audit/integrity/verify-range`：按链上位置区间校验（仅 AUDITOR/ADMIN，见第 6 节）

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

## 6. 防篡改哈希链与完整性校验

光记下来不够，还要能证明记录事后没被改动。这层能力由 `audit/integrity/` 提供：

### 怎么定义的

- 每条新记录**真正落库后**（`saveIfAbsent` 成功）追加为哈希链上的一环（`ChainEntry`）：
  `entryHash = SHA-256(记录内容规范化串 + 上一环 entryHash)`，首环的前驱为全零 `GENESIS`。
  每一环都依赖之前所有落库记录，形成可验证的先后关联。
- 事后任何人绕过接口直接改库（改内容、整条删记录、把记录换成别的、删/换/重排链上环节），校验时都会暴露：
  - 内容被改 → 重算哈希与链上登记值不一致（`HASH_MISMATCH`）；
  - 已入链记录整条消失、且未登记为留存策略清理 → 人为删除/被换成别的记录（`RECORD_MISSING`）；
  - 环节被删/换/重排 → 相邻环哈希衔接断开（`CHAIN_LINK_BROKEN`）。
- 校验报告会**精确定位第一处对不上的位置**（链上 position + eventId + 异常类型），不是只丢一句“校验失败”或一个条数。

### 并发与重试

- 链尾读取与 position 分配在一个短临界区内完成（仅哈希计算量级），多线程并发写入不断链、不乱序；
- 同一 `eventId` 只入链一次（仓储幂等兜底），调用方拿同一请求标识重试不会产生重复环节点；
- 校验只读仓储快照、不持有写入锁，且分批流式扫描（每批 500 条），不把全量记录拉进内存，也不会在正常写入的关键路径上阻塞写。

### 对历史记录与正常清理的兼容范围

校验不会把以下情况误报为篡改，而是**分开计数上报**：

| 情况 | 报告字段 | 说明 |
|---|---|---|
| 历史遗留：上线前已落库、没有链上环节的记录 | `legacyCount` | 不算异常；只表示“还没纳入这层关联” |
| 正常清理：记录被留存策略物理删除，且删除时已登记 | `purgedCount` | 链上环节仍在、记录已不在，不算异常 |
| 正常匿名化：记录被留存策略匿名化 | `anonymizedCount` | 匿名化时登记了“匿名化后内容哈希”，凭登记值通过校验；匿名化之后再被改动仍会被检出 |

正常清理与人为删除的区分靠两个登记处：

- `PurgeRegistry`：留存策略每物理删除一条记录，先登记其 `eventId`。校验时发现“链上环节在、记录不在”，**已登记 → `purgedCount`（正常清理）；未登记 → `RECORD_MISSING` 异常（人为删除）**，两者在报告里是分开的字段，不会混为一个条数。
- `AnonymizationRegistry`：匿名化时登记“匿名化后的内容哈希”，校验凭登记值放行正常匿名化；登记值对不上的改动仍是 `HASH_MISMATCH`。

**兼容边界**：`RECORD_MISSING` 判定以“删除时是否登记”为准。本登记能力上线**之前**就已经被物理清理掉的链上记录，没有登记记录，会被报为 `RECORD_MISSING`——这类历史缺口需要在上线的第一次校验时人工核对、一次性确认为基线；上线之后走的正常清理都会被登记，不会再误报。历史遗留（从未入链）的记录不受此影响，始终只计入 `legacyCount`。

### 校验入口

两种范围二选一（都省略 = 全量）：

```
GET /api/audit/integrity/verify?from=<ISO-8601>&to=<ISO-8601>          # 按落库时间范围
GET /api/audit/integrity/verify-range?fromPosition=1&toPosition=500    # 按链上位置区间（第几环到第几环）
```

- `verify`：`from`/`to` 可省略，表示不限；
- `verify-range`：`fromPosition` 必填（>=1），`toPosition` 省略表示到链尾；区间起点会回查区间外的前驱环，起点处的断链也能检出；区间不合法返回 400。

仅限 `AUDITOR`/`ADMIN` 角色（普通用户 403 `INTEGRITY_VERIFY_FORBIDDEN`，未认证 401）。返回 `IntegrityReport`：

```json
{
  "intact": true,            // 范围内整体是否完整
  "verifiedCount": 120,      // 通过哈希校验的记录数（含匿名化的）
  "anonymizedCount": 3,      // 其中凭匿名化登记哈希通过的
  "purgedCount": 5,          // 已登记为留存策略物理删除的链上环节数（正常清理）
  "legacyCount": 2,          // 尚未入链的历史遗留记录数
  "checkedPositions": 125,   // 本次实际检查的链上环节数（覆盖量）
  "firstAnomaly": null       // 第一处异常；若有则含 position/eventId/type/detail，
                             // type ∈ HASH_MISMATCH / RECORD_MISSING / CHAIN_LINK_BROKEN
}
```

## 7. 本地验证

### 运行测试（推荐）

```bash
mvn test
```

控制台会按“业务点”打印每个用例的通过情况，覆盖：正常留痕、失败与异常、并发与异步归属、脱敏、越权、留存策略、防篡改哈希链与完整性校验（共 50 个用例）。其中防篡改相关用例包括：人为删除/改动/替换记录的检出与定位、正常清理（删除/匿名化）不误报且与人为删除分开上报、按时间与按位置区间校验、并发写入与重试下关联不乱不重复、校验与写入并行互不阻塞。

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

# 6) 完整性校验：审计员/管理员可发起，返回 intact 与覆盖量
curl -s http://localhost:$PORT/api/audit/integrity/verify -H 'X-User: auditor' -H 'X-Roles: AUDITOR'

# 7) 按时间范围校验
curl -s "http://localhost:$PORT/api/audit/integrity/verify?from=2026-01-01T00:00:00Z" \
  -H 'X-User: root' -H 'X-Roles: ADMIN'

# 7b) 按链上位置区间校验（第 1 环到第 100 环）
curl -s "http://localhost:$PORT/api/audit/integrity/verify-range?fromPosition=1&toPosition=100" \
  -H 'X-User: root' -H 'X-Roles: ADMIN'

# 8) 普通用户发起校验 -> 403 INTEGRITY_VERIFY_FORBIDDEN
curl -s http://localhost:$PORT/api/audit/integrity/verify -H 'X-User: bob' -H 'X-Roles: USER'
```

## 8. 代码结构

```
audit/
  annotation/   @Audited、@Sensitive
  aspect/       AuditAspect（自动留痕、结果归类）
  context/      AuditContext（requestId/序列号，异步快照传播）
  masking/      脱敏服务
  security/     角色、访问控制、可区分拒绝原因
  repository/   审计仓储接口与内存实现（幂等、查询、过期处理）
  integrity/    防篡改哈希链（ChainEntry/HashChainService）、完整性校验
                （IntegrityVerificationService）、匿名化登记处（AnonymizationRegistry）、
                正常清理登记处（PurgeRegistry）
  service/      留痕服务、留存清理
  web/          上下文/鉴权过滤器、审计查询接口、完整性校验入口、全局异常处理
  config/       配置属性、异步线程池、定时开关
demo/           订单业务（@Audited 使用示例）与 HTTP 入口
```

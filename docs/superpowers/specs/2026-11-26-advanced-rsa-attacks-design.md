# 高级 RSA 攻击与 GUI 边界设计

## 1. 状态与目标

- 状态：已实现。五类高级攻击均已注册、测试并同步文档；GUI 仍为“设计中，尚不可用”。
- 实施顺序：先完成高级 RSA 攻击，再对 GUI 进行独立设计与实现。
- 当前基线：常见 RSA 参数填写与攻击路由已完成。
- 最终验证（2026-11-28）：未过滤 `cargo test --all-features --locked` 为 **381 passed**，`cargo test --doc --all-features --locked` 为 **0 passed**，`cargo fmt --all -- --check` 通过。Windows Clippy 因本机缺少 GNU target/MSYS2 工具链未完成；公开 Windows 工作流的结果以远端 Actions 运行记录为准。
- 文档原则：只有已实现、已注册、已测试并同步文档的能力才能标记为“已支持”。

本次实现目标：

1. 已知明文高位的 Coppersmith 攻击。
2. 部分素数已知高位的 Coppersmith 攻击。
3. 部分私钥指数 `d` 高位攻击。
4. Boneh–Durfee。
5. Franklin–Reiter。
6. 用共享预算和取消机制替代部分素数固定的 28 bit 拒绝逻辑。
7. 修复直接影响上述能力的旧代码问题。

非目标：

- 不保证恢复所有理论边界内的实例。
- 不把大范围纯暴力枚举包装成可靠能力。
- 不要求 Sage、Python、fplll 或其他外部格基工具。
- 本设计不实现 GUI；GUI 只定义与 CLI/JSON 的边界，后续单独评审。
- 不改变现有 JSON 成功结果结构和 `0/1/2` 退出码语义。

## 2. 模块边界

### 2.1 数学模块

新增 `src/math/lattice.rs`：

- 整数格基表示。
- 精确 Gram–Schmidt 正交化。
- 精确有理数 LLL 约化。
- 维度和迭代次数上限。
- 所有中间量使用整数或有理数，不使用浮点近似根。

新增 `src/math/polynomial.rs`：

- 模整数 `n` 的多项式表示。
- 加法、乘法、模幂、取模、首一化和 GCD。
- Franklin–Reiter 与 Coppersmith 共用。
- 当算法需要非可逆元逆元且条件不成立时，返回不支持，不产生伪解。

`rug` 增加 `rational` 特性以支持精确有理数。LLL 算法本身使用 Rust 实现，不引入外部格基程序。

本阶段固定资源上限：LLL 最大维度 `64`、最大迭代次数 `100_000`、多项式最大次数 `257`、取消检查批次 `1024`。这些常量集中管理，本阶段不通过 CLI 暴露。

### 2.2 攻击模块

新增 `src/attack/advanced/`：

- `coppersmith_message.rs`
- `coppersmith_factor.rs`
- `partial_d_msb.rs`
- `boneh_durfee.rs`
- `franklin_reiter.rs`

所有攻击继续实现现有 `Attack` trait，并复用 `Solution`：

- 能恢复 `p/q` 时返回 `pk`。
- 能直接恢复明文时返回 `m`。
- 已有 `pk` 且没有 `m` 时，由现有调度器解密 `c`。
- 所有候选必须通过确定性验证后才能返回成功。

### 2.3 控制模块

新增 `src/attack/control.rs`：

- `AttackControl` 可克隆，包含取消标志和共享候选预算。
- 提供 `check_cancelled`、`reserve_candidates` 和 `cancel`。
- 批量预留预算，避免每个候选都进行原子操作。
- 长循环、LLL 和多项式运算在批次边界检查取消。

## 3. 参数与接口

### 3.1 新增参数

| raw 字段 | CLI | 类型 | 语义 |
| --- | --- | --- | --- |
| `m_known` | `--m-known` | 整数 | 已知明文高位，即 `m >> m_unknown_bits` |
| `m_unknown_bits` | `--m-unknown-bits` | `usize` | 明文未知低位比特数 |
| `d_known_msb` | `--d-known-msb` | 整数 | 已知 `d` 高位，即 `d >> d_unknown_bits` |
| `d_unknown_bits` | `--d-unknown-bits` | `usize` | `d` 的未知低位比特数 |
| `related_c` | `--related-c` | 整数 | Franklin–Reiter 的第二组相关密文 |
| `related_a1` | `--related-a1` | 整数 | 第一组关系 `m1 = a1*x + b1 mod n` 的 `a1` |
| `related_b1` | `--related-b1` | 整数 | 第一组关系中的 `b1` |
| `related_a2` | `--related-a2` | 整数 | 第二组关系 `m2 = a2*x + b2 mod n` 的 `a2` |
| `related_b2` | `--related-b2` | 整数 | 第二组关系中的 `b2` |
| `search_budget` | `--search-budget` | `u64` | 本次调用共享的纯枚举候选预算 |

`related_c` 不复用 `c2`，因为 raw 的 `c2` 已表示第二组多密钥密文。

### 3.2 校验规则

- `m_known` 与 `m_unknown_bits` 必须同时提供。
- `d_known_msb` 与 `d_unknown_bits` 必须同时提供。
- Franklin–Reiter 的 `related_c` 和四个关系系数必须同时提供。
- 未知比特数不能超过对应模数或指数的合理规模；不合理输入返回参数错误。
- `search_budget = 0` 表示禁用纯暴力枚举，不禁用 Coppersmith。
- `search_budget` 默认值为 `2^28`。
- 新增字段必须进入 `Parameters::default`、`Display`、raw 解析、CLI 合并和 `has_direct_input`。
- 未知 raw 字段继续严格报错，不静默忽略。

## 4. 攻击设计

### 4.1 Coppersmith 已知明文高位

输入：`n`、`e`、`c`、`m_known`、`m_unknown_bits`。

令：

\[
m = m\_known \cdot 2^u + x,\qquad 0 \le x < 2^u
\]

构造：

\[
f(x) = (m\_known \cdot 2^u + x)^e - c \pmod n
\]

使用单变量 Coppersmith 小根恢复满足格子规模上限的 `x`。当 `2^u <= 4096` 时，先确定性穷举 `[0, 2^u)`，并对每个候选执行完整的 `m^e mod n = c` 验证；其余情况使用精确 Howgrave–Graham 格基。候选必须满足：

\[
m^e \bmod n = c
\]

成功后返回明文，不承诺同时分解 `n`。如果已知位数不满足保守条件或所需格子维度超过上限，返回 `Unsupported`。

### 4.2 Coppersmith 部分素数高位

复用 `partial_p`、`partial_q`，只对 `Orientation::MsbKnown` 优先使用格基。

令 `R = radix^k`，则：

\[
p = p\_known \cdot R + x,\qquad 0 \le x < R
\]

使用模 `p` 的因子恢复方法，并通过 `n mod p = 0` 恢复另一个因子。默认采用平衡素因子的保守条件；例如二进制未知部分要求 `R^4 < n`。条件不满足时不宣称可用。

候选必须满足：

- `p > 1` 且 `p < n`。
- `n mod p = 0`。
- `p` 和 `q = n/p` 通过素性检查。
- `PrivateKey::from_p_q` 成功。

已知低位或不适用格基时，仅使用共享预算内的枚举。ellipsis 推断出的多个 `k` 共享预算。

### 4.3 部分 `d` 高位

输入：`n`、`e`、`d_known_msb`、`d_unknown_bits`。

令：

\[
d = D \cdot 2^u + x,\qquad 0 \le x < 2^u
\]

由：

\[
ed - 1 = k\phi(n),\qquad 1 \le k < e
\]

以及：

\[
\phi(n) = n - (p+q) + 1
\]

推导每个 `k` 对应的 `p+q` 整数区间。小区间精确枚举并检查判别式是否为完全平方数；大区间提取素因子公共高位后调用 Coppersmith。

最终必须验证：

- `p*q = n`。
- `p`、`q` 为素数。
- `e*d mod phi(n) = 1`。
- 候选 `d` 位于输入指定的未知区间内。

不使用浮点近似根。

### 4.4 Boneh–Durfee

输入：`n`、`e`。

- 理论条件为 `d < n^0.292`。
- 默认保守参数固定为 `delta = 1/4`，即优先覆盖 `d < n^0.25`。
- 使用二元格基恢复 `p/q`。
- 格子维度、系数规模和迭代次数超过上限时返回 `Unsupported`。
- 候选必须通过 `p*q = n`、素性检查和私钥构造验证。

### 4.5 Franklin–Reiter

输入：`n`、`e`、`c`、`related_c`、`related_a1/b1/a2/b2`。

关系定义为：

\[
m_1 = a_1x + b_1 \pmod n,\qquad m_2 = a_2x + b_2 \pmod n
\]

密文满足：

\[
c = m_1^e \bmod n,\qquad related\_c = m_2^e \bmod n
\]

构造：

\[
f_1(x) = (a_1x+b_1)^e-c,\qquad f_2(x) = (a_2x+b_2)^e-related\_c
\]

通过模 `n` 多项式 GCD 恢复 `x`。候选必须同时通过两组加密往返验证。

为避免 `e = 65537` 等场景导致多项式展开和内存失控，本阶段设置 `e <= 257` 的固定安全上限；超过上限返回 `Unsupported`。若 GCD 过程需要不可逆元逆元且前提不成立，也返回 `Unsupported`。

## 5. 预算、取消与错误语义

### 5.1 共享预算

- 默认 `2^28` 个候选。
- `0` 禁用纯枚举。
- 仅纯枚举消费者共享预算；Coppersmith 不消耗候选预算，但受格子资源上限约束。
- `partial_p`、`partial_q` 和 ellipsis 的多次尝试使用同一预算。
- 使用 `AtomicU64` 批量预留，预留失败返回 `BudgetExceeded`。
- 搜索空间大于 `u64` 时直接与预算比较，不先转换为 `u64`。

### 5.2 协作取消

- `Attack::run_cancellable` 默认委托现有 `run`，保持旧攻击兼容。
- 新调度入口接受 `AttackControl`；现有公共入口使用默认控制对象。
- 任一攻击成功后，调度器取消其他仍在运行的攻击。
- 库调用方可以显式取消。
- GUI 通过终止子进程取消 CLI；不把 GUI 事件循环嵌入攻击运行时。

### 5.3 错误

新增：

- `Cancelled`：收到取消信号。
- `BudgetExceeded`：共享候选预算耗尽。
- `Unsupported`：输入超出本阶段安全条件或资源上限。

这些错误是攻击级结果，不改变现有退出码：

- 有攻击成功仍为 `0`。
- 所有攻击失败仍为 `1`。
- 参数、文件或运行时错误仍为 `2`。

## 6. 旧 `partial_prime` 修复

在引入新能力时一并修复以下已确认问题：

- `tick_size = max_iterations / 100` 在小预算下可能为 0。
- 候选为 0 时可能除零。
- `partial_p` 失败会阻止 `partial_q` 的独立尝试。
- ellipsis 多次尝试可能重复消耗预算。
- `radix^k` 超 `u64` 时处理过于粗糙。
- 候选未完成素性和因子验证就交给 `PrivateKey`。
- 进度条长度和实际预算不一致。

修复必须保留现有五个部分素数测试，并新增小预算、零预算、预算耗尽、双候选独立尝试和非法候选测试。

## 7. GUI 边界

GUI 在高级攻击稳定后单独设计，当前只固定以下边界：

- 独立 workspace crate 和 `rsacracker-gui.exe`。
- 使用 `egui/eframe`。
- 通过子进程调用 `rsacracker.exe --json`。
- 参数编辑、文件导入、攻击选择、进度、取消和结果导出均在 GUI 层完成。
- GUI 依赖不进入 CLI 核心包。
- Windows 发布包同时包含两个 EXE，并分别进行冒烟测试。

## 8. 测试策略

所有实现遵循 TDD：先写失败测试，确认失败原因正确，再写最小实现。

### 8.1 数学原语

- 已知格基的 LLL 约化结果。
- Gram–Schmidt 精确性。
- 多项式加减乘、模幂、取模和 GCD。
- 非可逆元和不合法多项式输入。

### 8.2 攻击

每个攻击至少包含：

- 一个确定性正例。
- 一个条件不满足的反例。
- 一个错误候选被拒绝的反例。
- 边界输入和资源上限测试。

测试密钥使用固定素数或固定种子，不依赖网络和随机运行结果。

### 8.3 接口

- raw 新字段解析、严格未知字段和非法值。
- CLI 新参数、中文帮助和直接输入判定。
- `--list` 与 `attack_details` 元数据。
- JSON 成功结果和退出码。
- 默认预算、零预算、预算耗尽和取消。
- `partial_p` 与 `partial_q` 的独立路由。

### 8.4 回归

- 保留基线测试并增加高级攻击回归。
- 每个里程碑运行完整测试。
- 最终运行格式检查、Clippy、未过滤完整测试、doc-tests；公开 Windows 工作流仅在获得推送授权后执行。

## 9. 文档同步规则

每个攻击里程碑必须在同一轮变更中更新：

1. 攻击实现和注册表。
2. `--list` / `attack_details`。
3. CLI 中文帮助。
4. README raw 字段表、题型矩阵、示例和能力状态。
5. 单元、集成、CLI/raw/JSON 和边界测试。

只有通过测试且文档同步完成后，才能把对应能力从“设计中”改为“已实现”。不允许在最终阶段统一补文档。

## 10. 实施里程碑

1. 控制、共享预算和 `partial_prime` 修复。
2. 多项式与精确 LLL 数学模块。
3. Coppersmith 部分素数高位，并接入预算回退。
4. Coppersmith 已知明文高位。
5. 部分 `d` 高位。
6. Boneh–Durfee。
7. Franklin–Reiter。
8. 全量回归、文档核对和公开 Windows 工作流验证。
9. GUI 独立设计、实施计划和验收。

## 11. 验收标准

- 五类高级攻击均注册到 `ATTACKS`，并出现在 `--list` 和 JSON 元数据中。
- 每个攻击有正例、反例、候选验证和资源上限测试。
- 部分素数不再依赖固定 28 bit 拒绝，而是使用共享预算、取消和已知高位 Coppersmith。
- 所有恢复结果都通过数学验证。
- 最终未过滤全量测试与 doc-tests 全部通过，具体数量见第 1 节。
- 格式检查通过；Clippy 和公开 Windows 工作流在具备相应工具链/推送授权后验证，未执行时明确记录且不标记为通过。
- README、中文帮助、raw 字段表和实际接口一致。
- GUI 未完成前不被标记为已实现。

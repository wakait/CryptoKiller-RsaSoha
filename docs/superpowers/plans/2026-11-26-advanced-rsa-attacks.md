# 高级 RSA 攻击实施计划
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
**Goal:** 在现有 Rust CLI 中实现五类可验证的高级 RSA 攻击，并以共享预算、协作取消和逐里程碑文档同步替代固定 28 bit 的部分素数限制。
**Architecture:** 保留现有 `Attack` trait、`Solution` 和 JSON 协议，新增默认委托旧 `run` 的 `run_cancellable`。纯 Rust 精确多项式与 LLL 模块提供数学原语；高级攻击只负责构造、恢复候选和确定性验证。GUI 不进入本计划。
**Tech Stack:** Rust 2021、rug Integer/Rational、Tokio、Clap 4.6、serde_json、indicatif、thiserror。
**Spec:** `docs/superpowers/specs/2026-11-26-advanced-rsa-attacks-design.md`
## Global Constraints
- 当前回归基线为 217 个测试通过；每个任务必须保留原有测试。
- 不引入 Sage、Python、fplll 或其他外部格基程序。
- `rug` 启用 `rational`；所有格基、根隔离和判别式判断使用整数或有理数，不使用浮点近似根。
- LLL 最大维度为 `64`，最大迭代次数为 `100_000`，多项式最大次数为 `257`，取消检查批次为 `1024`；常量集中在 `src/attack/control.rs`。
- `search_budget` 默认 `2^28`，`0` 禁用纯枚举；Coppersmith 不消耗候选预算。
- Franklin–Reiter 的 `e <= 257`；超过时返回 `Error::Unsupported`。
- Boneh–Durfee 默认 `delta = 1/4`，只宣称保守覆盖 `d < n^0.25`。
- 所有成功候选必须经过数学验证；能恢复 `p/q` 时返回 `pk`，只恢复明文时返回 `m`。
- 所有新增攻击实现 `run_cancellable`；`run` 以 `AttackControl::default()` 委托，格基和长循环必须接收并检查同一个控制对象。
- 保留退出码 `0/1/2`；`Cancelled`、`BudgetExceeded`、`Unsupported` 是攻击级错误。
- 每个任务同步代码、注册表、CLI 帮助、`--list`/JSON、测试和 README。
- 本计划不实现 GUI，也不把 GUI 依赖加入 CLI crate。
- 除非用户另有明确授权，不自动提交或推送；每个任务以工作区检查点交付。
## 文件结构
| 文件 | 职责 |
| --- | --- |
| `Cargo.toml` | 为 `rug` 启用 `rational` |
| `src/attack/control.rs` | 资源常量、取消标志、共享候选预算 |
| `src/attack/mod.rs` | 新错误、`run_cancellable`、高级攻击注册 |
| `src/lib.rs` | 带 `AttackControl` 的调度入口和成功后取消 |
| `src/params.rs` | 新 raw 字段、默认值、显示、合并和校验 |
| `src/main.rs` | 新 CLI 参数、直接输入判定和参数合并 |
| `src/math/polynomial.rs` | 模多项式、整数多项式、精确整数根、Sturm 序列、resultant |
| `src/math/lattice.rs` | 精确 Gram–Schmidt 和 LLL |
| `src/math/number_theory.rs` | 精确整数平方根、完全平方和整数次根 |
| `src/attack/partial_prime.rs` | 共享预算、取消、独立 `p/q` 尝试和候选验证 |
| `src/attack/advanced/coppersmith.rs` | 单变量 Howgrave–Graham 小根助手 |
| `src/attack/advanced/coppersmith_factor.rs` | 部分素数高位 Coppersmith |
| `src/attack/advanced/coppersmith_message.rs` | 已知明文高位 Coppersmith |
| `src/attack/advanced/partial_d_msb.rs` | 部分 `d` 高位攻击 |
| `src/attack/advanced/boneh_durfee.rs` | 保守 Boneh–Durfee |
| `src/attack/advanced/franklin_reiter.rs` | 双仿射相关明文 GCD 攻击 |
| `tests/cli.rs` | 中文帮助、raw/CLI/JSON、列表元数据和退出码 |
| `README.md` | 字段表、题型矩阵、示例、能力状态和限制 |
### Task 1: 控制、共享预算与 `partial_prime` 修复
**Files:**
- Create: `src/attack/control.rs`
- Modify: `Cargo.toml`
- Modify: `src/attack/mod.rs`
- Modify: `src/lib.rs`
- Modify: `src/params.rs`
- Modify: `src/main.rs`
- Modify: `src/attack/partial_prime.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: 现有 `Attack::run`、`Parameters`、`Error`、`run_specific_attacks_with_threads`。
- Produces:
  - `pub const DEFAULT_SEARCH_BUDGET: u64 = 1 << 28;`
  - `pub const CANCEL_CHECK_BATCH: usize = 1024;`
  - `pub const MAX_LLL_DIMENSION: usize = 64;`
  - `pub const MAX_LLL_ITERATIONS: usize = 100_000;`
  - `pub const MAX_POLYNOMIAL_DEGREE: usize = 257;`
  - `pub struct AttackControl`
  - `AttackControl::new(budget: u64) -> Self`
  - `AttackControl::default() -> Self`
  - `AttackControl::cancel(&self)`
  - `AttackControl::is_cancelled(&self) -> bool`
  - `AttackControl::check_cancelled(&self) -> Result<(), Error>`
  - `AttackControl::remaining(&self) -> u64`
  - `AttackControl::reserve_candidates(&self, count: u64) -> Result<(), Error>`
  - `Attack::run_cancellable(&self, params: &Parameters, pb: Option<&ProgressBar>, control: &AttackControl) -> Result<Solution, Error>`
  - `run_specific_attacks_with_control(params: &Parameters, attacks: &[Arc<dyn Attack + Sync + Send>], threads: usize, control: AttackControl) -> Result<Solution, Option<Factors>>`
  - `Parameters::search_budget: u64`
  - `Error::{Cancelled, BudgetExceeded, Unsupported}`
- [ ] **Step 1: 写控制与预算失败测试**
在 `src/attack/control.rs` 加入：
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    #[test]
    fn reservations_are_shared_across_clones() {
        let control = AttackControl::new(10);
        let clone = control.clone();
        control.reserve_candidates(6).unwrap();
        clone.reserve_candidates(4).unwrap();
        assert_eq!(clone.reserve_candidates(1), Err(Error::BudgetExceeded));
        assert_eq!(control.remaining(), 0);
    }
    #[test]
    fn cancellation_wins_over_budget() {
        let control = AttackControl::new(0);
        control.cancel();
        assert_eq!(control.reserve_candidates(1), Err(Error::Cancelled));
    }
    #[test]
    fn zero_budget_disables_enumeration() {
        let control = AttackControl::new(0);
        assert_eq!(control.reserve_candidates(1), Err(Error::BudgetExceeded));
    }
    #[test]
    fn concurrent_reservations_never_exceed_budget() {
        let control = Arc::new(AttackControl::new(100));
        let handles: Vec<_> = (0..8).map(|_| {
            let control = control.clone();
            thread::spawn(move || control.reserve_candidates(20))
        }).collect();
        let successes = handles.into_iter()
            .filter_map(|handle| handle.join().unwrap().ok()).count();
        assert_eq!(successes, 5);
        assert_eq!(control.remaining(), 0);
    }
}
```
在 `src/params.rs` 测试中加入：
```rust
#[test]
fn raw_parses_search_budget_and_display_round_trips() {
    let params = Parameters::try_from_raw("n = 3233\nsearch_budget = 0\n").unwrap();
    assert_eq!(params.search_budget, 0);
    assert!(params.to_string().contains("search_budget = 0"));
}
#[test]
fn raw_rejects_search_budget_above_u64() {
    let error = Parameters::try_from_raw("n = 3233\nsearch_budget = 18446744073709551616\n").unwrap_err();
    assert!(error.contains("search_budget"));
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test attack::control -- --nocapture'
Expected: 因 `control` 模块、`AttackControl` 和 `search_budget` 尚不存在而失败。
- [ ] **Step 3: 实现控制、错误和参数字段**
在 `src/attack/control.rs` 实现：
```rust
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use super::Error;
#[derive(Debug, Clone)]
pub struct AttackControl {
    cancelled: Arc<AtomicBool>,
    used: Arc<AtomicU64>,
    budget: u64,
}
impl AttackControl {
    pub fn new(budget: u64) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            used: Arc::new(AtomicU64::new(0)),
            budget,
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.used.load(Ordering::SeqCst))
    }
    pub fn check_cancelled(&self) -> Result<(), Error> {
        if self.is_cancelled() { Err(Error::Cancelled) } else { Ok(()) }
    }
    pub fn reserve_candidates(&self, count: u64) -> Result<(), Error> {
        self.check_cancelled()?;
        if count == 0 { return Ok(()); }
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                if self.is_cancelled() { return None; }
                used.checked_add(count)
                    .filter(|next| *next <= self.budget)
            })
            .map_err(|_| {
                if self.is_cancelled() { Error::Cancelled } else { Error::BudgetExceeded }
            })?;
        self.check_cancelled()
    }
}
impl Default for AttackControl {
    fn default() -> Self {
        Self::new(DEFAULT_SEARCH_BUDGET)
    }
}
```
在 `src/attack/mod.rs` 增加错误：
```rust
#[error("Attack cancelled")]
Cancelled,
#[error("Candidate search budget exceeded")]
BudgetExceeded,
#[error("Attack is unsupported for these parameters or resource limits")]
Unsupported,
```
增加默认兼容方法：
```rust
fn run_cancellable(
    &self,
    params: &Parameters,
    pb: Option<&ProgressBar>,
    _control: &AttackControl,
) -> Result<Solution, Error> {
    self.run(params, pb)
}
```
在 `Parameters` 增加 `pub search_budget: u64`，默认值为 `DEFAULT_SEARCH_BUDGET`。raw 识别 `searchbudget`，解析时使用 `IntegerArg` 后调用 `to_u64()`；转换失败必须记录字段级错误。`Display` 输出 `search_budget`。`AddAssign` 仅在左侧仍为默认预算时采用右侧值，保证 raw 自定义预算不会被省略的 CLI 默认值覆盖。
- [ ] **Step 4: 写调度与 `partial_prime` 失败测试**
在 `src/attack/partial_prime.rs` 增加测试：
```rust
#[test]
fn zero_budget_rejects_enumeration_without_panicking() {
    let p = Integer::from(1073741827u64);
    let q = Integer::from(2147483659u64);
    let params = Parameters {
        n: Some(&p * &q),
        search_budget: 0,
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(20),
            orient: Orientation::LsbKnown,
            known: p.clone() & ((Integer::from(1) << 11) - 1),
        }),
        ..Default::default()
    };
    let error = PartialPrimeAttack
        .run_cancellable(&params, None, &AttackControl::new(0))
        .unwrap_err();
    assert_eq!(error, Error::BudgetExceeded);
}
#[test]
fn failed_partial_p_does_not_block_partial_q() {
    let p = Integer::from(1073741827u64);
    let q = Integer::from(2147483659u64);
    let params = Parameters {
        n: Some(&p * &q),
        search_budget: 1 << 20,
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(20),
            orient: Orientation::LsbKnown,
            known: Integer::from(2),
        }),
        partial_q: Some(PartialPrime::Full(q.clone())),
        ..Default::default()
    };
    let solution = PartialPrimeAttack
        .run_cancellable(&params, None, &AttackControl::new(1 << 20))
        .unwrap();
    assert_eq!(solution.pk.unwrap().q(), q);
}
#[test]
fn zero_candidate_is_not_divided_into_n() {
    let params = Parameters {
        n: Some(Integer::from(15)),
        search_budget: 1,
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(1),
            orient: Orientation::LsbKnown,
            known: Integer::from(0),
        }),
        ..Default::default()
    };
    assert!(PartialPrimeAttack.run(&params, None).is_err());
}
```
- [ ] **Step 5: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test attack::partial_prime -- --nocapture'
Expected: 新 API 不存在，且旧实现遇到零预算仍进入枚举。
- [ ] **Step 6: 实现调度取消和预算枚举**
`_run_attacks` 的每个任务克隆同一个 `AttackControl` 并调用 `run_cancellable`。任一任务返回 `Ok` 时调用 `control.cancel()`。新公共入口使用传入控制对象；旧 `run_attacks*` 使用 `AttackControl::default()`，保持签名和行为兼容。
`PartialPrimeAttack::recover` 改为接收 `&AttackControl`：
1. 用 `Integer::from(radix).pow(k)` 计算搜索空间，不先转 `u64`。
2. 若空间为 `0` 返回 `NotFound`；若空间大于 `remaining()` 返回 `BudgetExceeded`。
3. 按最多 `CANCEL_CHECK_BATCH` 个候选批量预留预算。
4. 每批开始和每批结束调用 `check_cancelled()`。
5. 候选为 `0` 时跳过除法；候选必须满足 `1 < candidate < n`。
6. `n % candidate == 0` 后计算 `other = n / candidate`，要求 `other > 1`。
7. 用 `IsPrime` 拒绝已知合数，再调用 `PrivateKey::from_p_q` 验证。
8. 进度条长度设为实际枚举上限，`tick_size = max(1, limit / 100)`。
9. `partial_p` 与 `partial_q` 分别尝试；任一成功即返回，全部失败时优先保留 `BudgetExceeded`，其次 `Unsupported`，最后 `NotFound`。
10. ellipsis 的多个 `k` 复用同一控制对象，不重置预算。
- [ ] **Step 7: 接入 CLI/raw 并写接口测试**
在 `src/main.rs` 增加：
```rust
/// 本次调用共享的纯枚举候选预算；默认 2^28，0 表示禁用纯枚举。
#[clap(long)]
search_budget: Option<u64>,
```
把它加入 `has_direct_input` 和 `Parameters` 合并。`tests/cli.rs` 增加：
```rust
#[test]
fn help_and_list_expose_search_budget_contract() {
    let help = run_bin(&["-h"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--search-budget"));
    let list = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(report["attack_details"].as_array().unwrap().iter().any(|a| {
        a["name"] == "partial_prime"
            && a["required_parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "partial_p|partial_q|p|q")
    }));
}
```
- [ ] **Step 8: 运行 Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 原有 217 个测试和本任务新增测试全部通过。
- [ ] **Step 9: 同步 README 和工作区检查点**
更新 README：
- raw 字段表增加 `search_budget`。
- 命令行帮助快照增加 `--search-budget`。
- 将“固定 28 bit 拒绝”改为“共享预算、零预算禁用、可取消”。
- 增加默认预算和 `BudgetExceeded` 的说明。
- 保留“高级攻击尚未实现”的状态，不提前宣称 Coppersmith 可用。
Run: C:/Users/Admin/.cargo/bin/rustfmt.exe --edition 2021 --config skip_children=true src/attack/control.rs src/attack/mod.rs src/lib.rs src/params.rs src/main.rs src/attack/partial_prime.rs tests/cli.rs
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command "Set-Location -LiteralPath 'e:\Snow\Desktop\Tools_CTF\rascracker'; git diff --check; git status --short"
Expected: 格式与空白检查通过；不提交、不推送。
### Task 2: 精确多项式与 LLL 数学模块
**Files:**
- Modify: `Cargo.toml`
- Modify: `src/math/mod.rs`
- Modify: `src/math/number_theory.rs`
- Create: `src/math/polynomial.rs`
- Create: `src/math/lattice.rs`
**Interfaces:**
- Consumes: Task 1 的资源常量和 `AttackControl`。
- Produces:
  - `pub struct Polynomial { coeffs: Vec<Integer>, modulus: Integer }`
  - `Polynomial::new(coeffs: Vec<Integer>, modulus: Integer) -> Result<Self, Error>`
  - `Polynomial::zero(modulus: Integer) -> Self`
  - `Polynomial::one(modulus: Integer) -> Self`
  - `Polynomial::degree(&self) -> Option<usize>`
  - `Polynomial::add(&self, other: &Self) -> Self`
  - `Polynomial::sub(&self, other: &Self) -> Self`
  - `Polynomial::mul(&self, other: &Self) -> Self`
  - `Polynomial::pow(&self, exponent: u32) -> Self`
  - `Polynomial::rem(&self, divisor: &Self) -> Result<Self, Error>`
  - `Polynomial::monic(&self) -> Result<Self, Error>`
  - `Polynomial::gcd(&self, other: &Self) -> Result<Self, Error>`
  - `Polynomial::eval(&self, x: &Integer) -> Integer`
  - `Polynomial::from_affine_power(a: &Integer, b: &Integer, e: u32, c: &Integer, modulus: Integer) -> Self`
  - `pub fn integer_roots(coeffs: &[Integer], bound: &Integer, control: &AttackControl) -> Result<Vec<Integer>, Error>`
  - `pub struct BivariatePolynomial`
  - `BivariatePolynomial::canonicalize(&self) -> Self`
  - `BivariatePolynomial::pow(&self, exponent: u32) -> Self`
  - `BivariatePolynomial::resultant(&self, other: &Self, control: &AttackControl) -> Result<Vec<Integer>, Error>`
  - `pub fn lll(basis: &[Vec<Integer>], control: &AttackControl) -> Result<Vec<Vec<Integer>>, Error>`
  - `pub fn gram_schmidt(basis: &[Vec<Integer>]) -> Result<(mu: Vec<Vec<Rational>>, norms: Vec<Rational>), Error>`
  - `integer_sqrt(n: &Integer) -> Integer`
  - `integer_nth_root(n: &Integer, degree: u32) -> Integer`
  - `is_perfect_square(n: &Integer) -> Option<Integer>`
- [ ] **Step 1: 写多项式失败测试**
```rust
#[test]
fn modular_polynomial_arithmetic_and_gcd() {
    let n = Integer::from(3233);
    let f = Polynomial::new(vec![7.into(), 0.into(), 1.into()], n.clone()).unwrap();
    let g = Polynomial::new(vec![7.into(), (-1).into()], n).unwrap();
    assert_eq!(f.gcd(&g).unwrap().coeffs, vec![Integer::from(1)]);
    assert_eq!(f.eval(&Integer::from(5)), Integer::from(32));
}
#[test]
fn modular_polynomial_add_sub_mul_pow_and_rem() {
    let f = Polynomial::new(vec![1.into(), 2.into(), 1.into()], 101.into()).unwrap();
    let g = Polynomial::new(vec![1.into(), 1.into()], 101.into()).unwrap();
    assert_eq!(f.add(&g).coeffs, vec![2.into(), 3.into(), 1.into()]);
    assert_eq!(f.sub(&g).coeffs, vec![0.into(), 1.into(), 1.into()]);
    assert_eq!(f.mul(&g).coeffs, vec![1.into(), 3.into(), 3.into(), 1.into()]);
    assert_eq!(f.pow(2).coeffs, vec![1.into(), 4.into(), 6.into(), 4.into(), 1.into()]);
    assert_eq!(f.rem(&g).unwrap().degree(), None);
}
#[test]
fn affine_power_matches_direct_expansion() {
    let f = Polynomial::from_affine_power(&2.into(), &3.into(), 3, &17.into(), 101.into());
    assert_eq!(f.eval(&4.into()), 1.into()); // (2*4+3)^3 - 17 = 1314, mod 101
}
#[test]
fn non_invertible_leading_coefficient_is_unsupported() {
    let f = Polynomial::new(vec![1.into(), 61.into()], 3233.into()).unwrap();
    assert_eq!(f.monic().unwrap_err(), Error::Unsupported);
}
#[test]
fn integer_roots_are_exact_and_bounded() {
    let control = AttackControl::default();
    // (x-3)(x+2)(x-9) = x^3 - 10x^2 + 3x + 54
    let roots = integer_roots(
        &[54.into(), 3.into(), (-10).into(), 1.into()],
        &10.into(),
        &control,
    ).unwrap();
    assert_eq!(roots, vec![(-2).into(), 3.into(), 9.into()]);
}
```
- [ ] **Step 2: 写整数根与 LLL 失败测试**
```rust
#[test]
fn integer_square_and_fourth_root_are_exact() {
    assert_eq!(integer_sqrt(&100.into()), 10.into());
    assert_eq!(is_perfect_square(&101.into()), None);
    assert_eq!(integer_nth_root(&81.into(), 4), 3.into());
    assert_eq!(integer_nth_root(&80.into(), 4), 2.into());
}
#[test]
fn lll_reduces_known_basis() {
    let control = AttackControl::default();
    let basis = [vec![1.into(), 0.into()], vec![100.into(), 1.into()]];
    let (mu, norms) = gram_schmidt(&basis).unwrap();
    assert_eq!(mu[1][0], rug::Rational::from(100));
    assert_eq!(norms, vec![rug::Rational::from(1), rug::Rational::from(1)]);
    let reduced = lll(&basis, &control).unwrap();
    assert_eq!(reduced, vec![vec![1.into(), 0.into()], vec![0.into(), 1.into()]]);
}
#[test]
fn lll_rejects_dimension_above_limit() {
    let basis = vec![vec![Integer::from(0); MAX_LLL_DIMENSION + 1]; MAX_LLL_DIMENSION + 1];
    assert_eq!(lll(&basis, &AttackControl::default()).unwrap_err(), Error::Unsupported);
}
```
- [ ] **Step 3: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test math::polynomial math::lattice -- --nocapture'
Expected: 模块和函数不存在。
- [ ] **Step 4: 实现精确多项式**
`Polynomial` 的系数按次数从低到高保存并归一化到 `[0, n)`。构造时拒绝 `n <= 1`、空系数和超过 `MAX_POLYNOMIAL_DEGREE` 的输入。乘法、模幂和取模均检查次数上限。`rem` 使用多项式长除法；首项系数不可逆时返回 `Unsupported`。`gcd` 使用欧几里得算法并返回首一结果。
`integer_roots` 使用精确 Sturm 序列：
1. 去掉高次零系数，构造整数多项式 `p` 和导数 `p'`。
2. 用 `Rational` 多项式长除法生成 `p0=p`、`p1=p'`、`pnext=-rem(pprev,pcurrent)`。
3. 在有理端点 `-bound-1` 和 `bound+1` 计算符号变化数。
4. 递归二分区间；零根区间丢弃，单根区间继续缩到宽度不超过 `1`。
5. 对宽度不超过 `1` 的区间取整数候选，验证 `p(candidate) == 0` 和 `|candidate| <= bound`。
6. 排序、去重，并在递归批次边界检查取消。
整数次根使用二进制搜索，上界为 `2^ceil(bit_length/degree)`，全程整数比较。
- [ ] **Step 5: 实现精确 LLL**
`gram_schmidt` 对每一行使用 `Rational` 计算：
\[
\mu_{i,j}=\frac{\langle b_i,b_j^*\rangle}{\langle b_j^*,b_j^*\rangle},\qquad
b_i^*=b_i-\sum_{j<i}\mu_{i,j}b_j^*.
\]
`lll` 使用 `delta = 3/4`：
1. 拒绝空基、非方阵、维度超过 `64` 和线性相关基。
2. 从 `k=1` 开始，按 `j=k-1..0` 做精确最近整数 size reduction。
3. 若 Lovász 条件不成立则交换相邻行，否则 `k += 1`。
4. 每 `1024` 次迭代检查取消；超过 `100_000` 次返回 `Unsupported`。
5. 最近整数函数必须对正负数和半整数给出确定规则，测试固定该规则。
- [ ] **Step 6: 实现 Boneh–Durfee 所需双变量助手**
`BivariatePolynomial` 使用 `BTreeMap<(u32,u32,u32),Integer>` 保存 `u^a x^b y^c`。`canonicalize` 对每一项取 `r=min(b,c)`，按二项式展开：
\[
u^a x^b y^c=\sum_{s=0}^{r}\binom{r}{s}(-1)^{r-s}u^{a+s}x^{b-r}y^{c-r}.
\]
`resultant` 对两个关于 `x` 的多项式构造 Sylvester 矩阵，用 Bareiss 整数行列式算法计算，不使用浮点。次数超过 `MAX_POLYNOMIAL_DEGREE` 或取消时返回对应错误。
- [ ] **Step 7: 运行 Green 与全量回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 217 个基线测试和数学模块测试全部通过。
- [ ] **Step 8: 同步 README**
在“能力状态”中增加“精确多项式与 LLL 已实现，但高级攻击仍待接入”；在构建说明中记录 `rug` 的 `rational` 特性。不得把数学模块完成写成高级攻击已完成。
### Task 3: Coppersmith 部分素数高位与预算回退
**Files:**
- Create: `src/attack/advanced/mod.rs`
- Create: `src/attack/advanced/coppersmith.rs`
- Create: `src/attack/advanced/coppersmith_factor.rs`
- Modify: `src/attack/mod.rs`
- Modify: `src/attack/partial_prime.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: `Polynomial`、`integer_roots`、`lll`、`AttackControl`、`PartialPrime`。
- Produces:
  - `pub struct CoppersmithFactorAttack`
  - `small_roots_monic(f: &Polynomial, modulus: &Integer, beta: &Rational, bound: &Integer, control: &AttackControl) -> Result<Vec<Integer>, Error>`
  - `PartialPrimeAttack` 对 `Orientation::MsbKnown` 优先调用 Coppersmith。
- [ ] **Step 1: 写攻击失败测试**
```rust
#[test]
fn coppersmith_factor_recovers_large_unknown_lsb_with_zero_bruteforce_budget() {
    let p = Integer::from_str("112219243609243706223486619551298085362360091408633161457003404046681540344297").unwrap();
    let q = Integer::from_str("64052533192509995760322742160163582601357132095571262796409705234000154367147").unwrap();
    let unknown = 40usize;
    let params = Parameters {
        n: Some(&p * &q),
        search_budget: 0,
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(unknown),
            orient: Orientation::MsbKnown,
            known: p.clone() >> unknown,
        }),
        ..Default::default()
    };
    let solution = PartialPrimeAttack
        .run_cancellable(&params, None, &AttackControl::new(0))
        .unwrap();
    assert_eq!(solution.pk.unwrap().p(), p);
}
#[test]
fn coppersmith_factor_rejects_bound_outside_conservative_condition() {
    let p = Integer::from(61);
    let q = Integer::from(53);
    let params = Parameters {
        n: Some(&p * &q),
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(4),
            orient: Orientation::MsbKnown,
            known: Integer::from(3),
        }),
        ..Default::default()
    };
    assert_eq!(CoppersmithFactorAttack.run(&params, None).unwrap_err(), Error::Unsupported);
}
#[test]
fn coppersmith_factor_rejects_wrong_known_bits() {
    let params = Parameters {
        n: Some(Integer::from(3233)),
        partial_p: Some(PartialPrime::Partial {
            radix: 2,
            k: Some(2),
            orient: Orientation::MsbKnown,
            known: Integer::from(99),
        }),
        ..Default::default()
    };
    assert_eq!(CoppersmithFactorAttack.run(&params, None), Err(Error::NotFound));
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test coppersmith_factor -- --nocapture'
Expected: 攻击和助手不存在。
- [ ] **Step 3: 实现 Howgrave–Graham 小根助手**
`small_roots_monic` 执行：
1. 要求 `f` 首一，次数 `d <= MAX_POLYNOMIAL_DEGREE`。
2. 用精确整数幂检查保守界：
   \[
   X^{d\cdot \operatorname{denom}(\beta)^2}
   < n^{\operatorname{numer}(\beta)^2}.
   \]
3. 对 `m=1,2,...`，令 `t=d*m/2`，维度 `dim=d*m+t`；首次超过 `64` 时停止。
4. 构造行：
   - 对 `i=0..m`（不含 `m`）、`j=0..d`（不含 `d`），加入 `x^j n^(m-i) f(x)^i`；
   - 对 `i=0..t`（不含 `t`），加入 `x^i f(x)^m`。
5. 以 `x^k` 为列，令 `B[row][k]=coeff_k * X^k`，调用 `lll`。
6. 每行除以 `X^k` 还原整数多项式，调用 `integer_roots`。
7. 过滤 `0 <= root < X` 且 `f.eval(root) == 0`，排序去重。
8. 所有允许维度均未命中返回 `NotFound`；输入不满足保守界或最小维度超过上限返回 `Unsupported`。
- [ ] **Step 4: 实现因子攻击和 `partial_prime` 路由**
`CoppersmithFactorAttack` 对每个 `MsbKnown` 部分素数构造：
\[
R=\mathrm{radix}^k,\quad f(x)=x+p\_known\cdot R,\quad X=R,\quad \beta=1/2.
\]
每个根构造 `p=p_known*R+x`，验证 `1<p<n`、`p*q=n`、素性和 `PrivateKey::from_p_q`。`PartialPrimeAttack` 对 MSB 先走该路径；Coppersmith 返回 `Unsupported` 或 `NotFound` 后，才使用 Task 1 的共享预算枚举。LSB 保持枚举。
- [ ] **Step 5: 注册、CLI/JSON 测试和 README**
注册 `coppersmith_factor`，元数据为 `&["n", "e", "partial_p|partial_q"]`。
`tests/cli.rs` 增加列表断言：
```rust
#[test]
fn json_list_contains_coppersmith_factor() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"].as_array().unwrap().iter()
        .find(|a| a["name"] == "coppersmith_factor").unwrap();
    assert_eq!(attack["required_parameters"], serde_json::json!(["n", "e", "partial_p|partial_q"]));
}
```
README 将“部分素数高位 Coppersmith”移入已实现矩阵，补充 `search_budget=0` 仍可走格基、LSB 仍需预算，以及保守条件 `R^4 < n`。
- [ ] **Step 6: Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 全部通过。
### Task 4: Coppersmith 已知明文高位
**Files:**
- Create: `src/attack/advanced/coppersmith_message.rs`
- Modify: `src/attack/advanced/mod.rs`
- Modify: `src/attack/mod.rs`
- Modify: `src/params.rs`
- Modify: `src/main.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: `small_roots_monic`、`Polynomial::from_affine_power`。
- Produces:
  - `pub struct CoppersmithMessageAttack`
  - `Parameters::{m_known: Option<Integer>, m_unknown_bits: Option<usize>}`
  - CLI `--m-known`、`--m-unknown-bits`
  - `Parameters::validate_advanced_inputs() -> Result<(), String>`
- [ ] **Step 1: 写 raw/CLI 失败测试**
```rust
#[test]
fn raw_parses_message_msb_fields() {
    let params = Parameters::try_from_raw("n = 3233\nm_known = 21\nm_unknown_bits = 1\n").unwrap();
    assert_eq!(params.m_known, Some(21.into()));
    assert_eq!(params.m_unknown_bits, Some(1));
    assert!(params.to_string().contains("m_unknown_bits = 1"));
}
#[test]
fn message_msb_fields_must_be_paired() {
    let error = Parameters::try_from_raw("n = 3233\nm_known = 21\n").unwrap_err();
    assert!(error.contains("m_known"));
    assert!(error.contains("m_unknown_bits"));
}
```
```rust
#[test]
fn cli_coppersmith_message_decrypts_and_reports_attack() {
    let output = run_bin(&[
        "-n", "1000036000099", "-e", "5", "-c", "819449521559",
        "--m-known", "964", "--m-unknown-bits", "7",
        "--attack=coppersmith_message", "--threads=1", "--json",
    ]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["attack"], "coppersmith_message");
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test coppersmith_message -- --nocapture'
Expected: 字段、CLI 参数和攻击不存在。
- [ ] **Step 3: 实现字段、校验和攻击**
`Parameters` 增加两个字段并接入 raw、`Display`、`AddAssign` 和 `has_direct_input`。`validate_advanced_inputs` 要求两字段同时存在或同时缺失，并要求 `m_unknown_bits <= n.significant_bits()`。CLI 在构建 `Parameters` 后调用该函数，错误以退出码 `2` 和 JSON `error` 返回。
攻击构造：
\[
f(x)=(m\_known\cdot 2^u+x)^e-c\pmod n,\quad X=2^u,\quad \beta=1.
\]
使用 `small_roots_monic` 恢复 `x`，构造 `m=m_known*2^u+x`，验证 `0<=x<X` 和 `m^e mod n=c`，返回 `Solution::new_m`。`e > 257`、`X^e >= n` 或最小格维超过 `64` 返回 `Unsupported`；未命中返回 `NotFound`。
- [ ] **Step 4: 写攻击正反例**
```rust
#[test]
fn coppersmith_message_recovers_fixed_vector() {
    let p = Integer::from(1000003);
    let q = Integer::from(1000033);
    let n = &p * &q;
    let m = Integer::from(123456);
    let c = m.clone().pow_mod(&5.into(), &n).unwrap();
    let params = Parameters {
        n: Some(n), c: Some(c), m_known: Some(964.into()),
        m_unknown_bits: Some(7), ..Default::default()
    };
    assert_eq!(CoppersmithMessageAttack.run(&params, None).unwrap().m, Some(m));
}
#[test]
fn coppersmith_message_rejects_wrong_ciphertext() {
    let params = Parameters {
        n: Some((Integer::from(1000003) * 1000033).into()),
        c: Some(0.into()), m_known: Some(964.into()),
        m_unknown_bits: Some(7), ..Default::default()
    };
    assert_eq!(CoppersmithMessageAttack.run(&params, None), Err(Error::NotFound));
}
#[test]
fn coppersmith_message_rejects_excessive_unknown_bits() {
    let params = Parameters {
        n: Some(3233.into()), c: Some(1.into()), m_known: Some(0.into()),
        m_unknown_bits: Some(12), ..Default::default()
    };
    assert_eq!(CoppersmithMessageAttack.run(&params, None).unwrap_err(), Error::Unsupported);
}
```
- [ ] **Step 5: 注册并同步文档**
注册 `coppersmith_message`，元数据为 `&["n", "e", "c", "m_known+m_unknown_bits"]`。
在 `tests/cli.rs` 的 `-h`/`--help` 期望列表加入两个新参数，并在 JSON 列表测试中断言攻击存在。README 增加 raw 字段、CLI 帮助、题型矩阵和固定示例；明确“恢复明文，不承诺同时分解 `n`”。
- [ ] **Step 6: Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 全部通过。
### Task 5: 部分私钥指数 `d` 高位
**Files:**
- Create: `src/attack/advanced/partial_d_msb.rs`
- Modify: `src/attack/advanced/mod.rs`
- Modify: `src/attack/mod.rs`
- Modify: `src/params.rs`
- Modify: `src/main.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: `AttackControl`、`integer_sqrt`、`is_perfect_square`、Coppersmith 因子助手、`PrivateKey`；实现 `run_cancellable`。
- Produces:
  - `pub struct PartialDMsbAttack`
  - `Parameters::{d_known_msb: Option<Integer>, d_unknown_bits: Option<usize>}`
  - CLI `--d-known-msb`、`--d-unknown-bits`
- [ ] **Step 1: 写字段和攻击失败测试**
```rust
#[test]
fn raw_parses_d_msb_fields() {
    let params = Parameters::try_from_raw("n = 3233\nd_known_msb = 171\nd_unknown_bits = 4\n").unwrap();
    assert_eq!(params.d_known_msb, Some(171.into()));
    assert_eq!(params.d_unknown_bits, Some(4));
}
#[test]
fn partial_d_msb_recovers_fixed_key() {
    let params = Parameters {
        n: Some(3233.into()), e: 17.into(), d_known_msb: Some(171.into()),
        d_unknown_bits: Some(4), ..Default::default()
    };
    let solution = PartialDMsbAttack.run(&params, None).unwrap();
    let pk = solution.pk.unwrap();
    assert_eq!(pk.p(), 61.into());
    assert_eq!(pk.q(), 53.into());
    assert_eq!(pk.d, 2753.into());
}
#[test]
fn partial_d_msb_rejects_candidate_outside_interval() {
    let params = Parameters {
        n: Some(3233.into()), e: 17.into(), d_known_msb: Some(172.into()),
        d_unknown_bits: Some(4), ..Default::default()
    };
    assert_eq!(PartialDMsbAttack.run(&params, None), Err(Error::NotFound));
}
#[test]
fn partial_d_msb_honors_pre_cancelled_control() {
    let params = Parameters {
        n: Some(3233.into()), e: 17.into(), d_known_msb: Some(171.into()),
        d_unknown_bits: Some(4), ..Default::default()
    };
    let control = AttackControl::default();
    control.cancel();
    assert_eq!(PartialDMsbAttack.run_cancellable(&params, None, &control), Err(Error::Cancelled));
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test partial_d_msb -- --nocapture'
Expected: 字段和攻击不存在。
- [ ] **Step 3: 实现整数区间推导**
令 `D=d_known_msb`、`u=d_unknown_bits`、`U=2^u`、`d=D*U+x`。对每个 `k=1..e-1`：
1. 解线性同余 `e*x ≡ -(e*D*U-1) (mod k)`。设 `g=gcd(e,k)`；右边不能被 `g` 整除时跳过。
2. 得到一个公差 `step=k/g` 的 `x` 序列，只保留 `0<=x<U`。
3. 对每个可行 `x` 计算：
   \[
   s=p+q=n+1-\frac{e(D U+x)-1}{k}.
   \]
4. 将可行 `s` 合并为连续区间和步进集合；要求 `s>=2` 且 `s^2>=4n`。
5. 小区间按共享预算枚举判别式 `s^2-4n`；完全平方时构造 `p/q`。
6. 大区间用 `s_lo` 和 `s_hi` 推导平衡因子 `p` 的整数范围，取公共高位；若 `R^4<n`，把该高位交给 Coppersmith 因子助手。
候选必须满足 `p*q=n`、素性、`e*d mod phi=1`、`D*U<=d<(D+1)*U` 和 `PrivateKey::from_p_q` 成功。任何不满足条件的候选继续搜索，不返回伪解。
- [ ] **Step 4: 处理资源上限和取消**
- 每处理 `1024` 个 `k` 或候选检查取消。
- 小区间枚举使用同一个 `AttackControl`，预算耗尽返回 `BudgetExceeded`。
- 若所有大区间提取到的已知高位都不满足 `R^4<n`，返回 `Unsupported`。
- 不使用浮点根；区间端点使用 `sqrt_rem` 的整数上下界。
- [ ] **Step 5: 注册、CLI 和文档**
注册 `partial_d_msb`，元数据为 `&["n", "e", "d_known_msb+d_unknown_bits"]`。
CLI 增加两个参数并加入 `has_direct_input`。`validate_advanced_inputs` 要求两字段成对出现且 `d_unknown_bits <= n.significant_bits()`。README 增加字段、矩阵、`n=3233/e=17/d_known_msb=171/d_unknown_bits=4` 示例和“最终验证 `ed mod phi=1`”说明。
- [ ] **Step 6: Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 全部通过。
### Task 6: 保守 Boneh–Durfee
**Files:**
- Create: `src/attack/advanced/boneh_durfee.rs`
- Modify: `src/attack/advanced/mod.rs`
- Modify: `src/attack/mod.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: `AttackControl`、`BivariatePolynomial`、`lll`、`integer_roots`、`integer_nth_root`、`integer_sqrt`、`is_perfect_square`。
- Produces: `pub struct BonehDurfeeAttack`；模块私有 `fn candidate_to_key(n: Integer, e: Integer, d: Integer, y: Integer) -> Option<PrivateKey>`；实现 `run_cancellable`。
- [ ] **Step 1: 写攻击失败测试**
```rust
#[test]
fn boneh_durfee_recovers_conservative_small_d() {
    // p=61, q=53, phi=3120, d=5, e=2497, k=4.
    let params = Parameters { n: Some(3233.into()), e: 2497.into(), ..Default::default() };
    let solution = BonehDurfeeAttack.run(&params, None).unwrap();
    let pk = solution.pk.unwrap();
    assert_eq!(pk.p(), 61.into());
    assert_eq!(pk.q(), 53.into());
    assert_eq!(pk.d, 5.into());
}
#[test]
fn boneh_durfee_rejects_invalid_candidate() {
    assert!(candidate_to_key(3233.into(), 2497.into(), 6.into(), (-57).into()).is_none());
}
#[test]
fn boneh_durfee_returns_not_found_for_large_d_instance() {
    let params = Parameters { n: Some(3233.into()), e: 17.into(), ..Default::default() };
    assert_eq!(BonehDurfeeAttack.run(&params, None), Err(Error::NotFound));
}
#[test]
fn boneh_durfee_honors_pre_cancelled_control() {
    let params = Parameters { n: Some(3233.into()), e: 2497.into(), ..Default::default() };
    let control = AttackControl::default();
    control.cancel();
    assert_eq!(BonehDurfeeAttack.run_cancellable(&params, None, &control), Err(Error::Cancelled));
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test boneh_durfee -- --nocapture'
Expected: 攻击不存在。
- [ ] **Step 3: 实现标准二元格基**
固定 `delta=1/4`，计算：
```text
A = floor((n+1)/2)
X = 2*integer_nth_root(n,4) + 2
Y = integer_sqrt(n) + 1
U = X*Y + 1
f(u,x,y) = 1 + x*(A+y)
```
按 `m = 4,6,7,8` 构造，`t=(1-2*delta)*m=m/2`：
1. x-shift：`k=0..m`、`i=0..m-k`，加入 `x^i e^(m-k) f^k`。
2. 收集 x-shift 单项式并按 `(u,x,y)` 排序。
3. y-shift：`j=1..t`、`k=floor(m/t)*j..m`，加入 `y^j e^(m-k) f^k`，并追加单项式 `u^k y^j`。
4. 每行常数列为 `g(0,0,0)`；列 `(a,b,c)` 的系数为 `g` 中该单项式系数乘 `U^a X^b Y^c`。
5. 维度超过 `64` 返回 `Unsupported`，否则调用 `lll`。
- [ ] **Step 4: 还原多项式并恢复候选**
对约化基的前两行线性无关组合：
1. 用 `u=w*z+1` 展开每个单项式 `(wz+1)^a w^b z^c`。
2. 每列除以 `U^a X^b Y^c`，还原整数二元多项式 `h1/h2`。
3. 使用同一个 `control` 计算 `resultant`；跳过零 resultant 和常数 resultant。
4. 用 `integer_roots(resultant,Y)` 枚举 `y`。
5. 对每个 `y`，把 `h1(x,y)` 视为一元多项式，用 `integer_roots(...,X)` 枚举 `x`。
6. 要求 `x` 为偶数，`d=(1+x*(A+y))/e` 可精确整除且为正。
7. 令 `s=-2*y`，验证 `s^2-4n` 为完全平方，构造 `p=(s+sqrt)/2`、`q=(s-sqrt)/2`。
8. 验证 `p*q=n`、素性、`e*d mod phi=1` 和 `PrivateKey::from_p_q`。
任一候选验证失败就继续；全部失败返回 `NotFound`。达到资源上限返回 `Unsupported`。
- [ ] **Step 5: 注册和文档**
注册 `boneh_durfee`，元数据 `&["n","e"]`，速度 `Slow`。README 增加题型矩阵，明确理论条件 `d<n^0.292`、本实现默认保守 `d<n^0.25`、需要平衡素因子，且候选必须恢复并验证 `p/q`。
- [ ] **Step 6: Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 全部通过。
### Task 7: Franklin–Reiter 相关明文
**Files:**
- Create: `src/attack/advanced/franklin_reiter.rs`
- Modify: `src/attack/advanced/mod.rs`
- Modify: `src/attack/mod.rs`
- Modify: `src/params.rs`
- Modify: `src/main.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
**Interfaces:**
- Consumes: `AttackControl`、`Polynomial::from_affine_power`、`Polynomial::gcd`；实现 `run_cancellable`。
- Produces:
  - `pub struct FranklinReiterAttack`
  - `Parameters::{related_c, related_a1, related_b1, related_a2, related_b2: Option<Integer>}`
  - CLI `--related-c`、`--related-a1`、`--related-b1`、`--related-a2`、`--related-b2`
- [ ] **Step 1: 写字段和攻击失败测试**
```rust
#[test]
fn raw_parses_franklin_reiter_fields() {
    let params = Parameters::try_from_raw(
        "n = 3233\nrelated_c = 1411\nrelated_a1 = 2\nrelated_b1 = 3\nrelated_a2 = 3\nrelated_b2 = 5\n"
    ).unwrap();
    assert_eq!(params.related_c, Some(1411.into()));
    assert_eq!(params.related_a2, Some(3.into()));
}
#[test]
fn franklin_reiter_recovers_related_message() {
    let params = Parameters {
        n: Some(3233.into()), e: 3.into(), c: Some(1680.into()),
        related_c: Some(1411.into()), related_a1: Some(2.into()),
        related_b1: Some(3.into()), related_a2: Some(3.into()),
        related_b2: Some(5.into()), ..Default::default()
    };
    let solution = FranklinReiterAttack.run(&params, None).unwrap();
    assert_eq!(solution.m, Some(7.into()));
}
#[test]
fn franklin_reiter_rejects_wrong_related_ciphertext() {
    let params = Parameters {
        n: Some(3233.into()), e: 3.into(), c: Some(1680.into()),
        related_c: Some(0.into()), related_a1: Some(2.into()),
        related_b1: Some(3.into()), related_a2: Some(3.into()),
        related_b2: Some(5.into()), ..Default::default()
    };
    assert_eq!(FranklinReiterAttack.run(&params, None), Err(Error::NotFound));
}
#[test]
fn franklin_reiter_rejects_excessive_exponent() {
    let params = Parameters {
        n: Some(3233.into()), e: 65537.into(), c: Some(1680.into()),
        related_c: Some(1411.into()), related_a1: Some(2.into()),
        related_b1: Some(3.into()), related_a2: Some(3.into()),
        related_b2: Some(5.into()), ..Default::default()
    };
    assert_eq!(FranklinReiterAttack.run(&params, None).unwrap_err(), Error::Unsupported);
}
#[test]
fn franklin_reiter_rejects_non_invertible_relation() {
    let params = Parameters {
        n: Some(3233.into()), e: 3.into(), c: Some(1680.into()),
        related_c: Some(1.into()), related_a1: Some(61.into()),
        related_b1: Some(0.into()), related_a2: Some(0.into()),
        related_b2: Some(1.into()), ..Default::default()
    };
    assert_eq!(FranklinReiterAttack.run(&params, None).unwrap_err(), Error::Unsupported);
}
```
- [ ] **Step 2: 运行测试确认 Red**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test franklin_reiter -- --nocapture'
Expected: 字段和攻击不存在。
- [ ] **Step 3: 实现 GCD 恢复**
攻击要求五个 Franklin–Reiter 字段全部存在或全部缺失。`e > 257` 返回 `Unsupported`。先要求关系矩阵行列式 `a1*b2-a2*b1` 在模 `n` 下可逆；否则返回 `Unsupported`。构造：
```rust
let f1 = Polynomial::from_affine_power(a1, b1, e, c, n);
let f2 = Polynomial::from_affine_power(a2, b2, e, related_c, n);
let g = f1.gcd(&f2)?.monic()?;
```
若 `g` 为常数返回 `NotFound`；若次数不是 `1` 返回 `Unsupported`，因为模合数多项式不能直接当作整数多项式求根。线性首一 GCD 的根为 `x = (-g.coeffs[0]) mod n`，每个候选验证：
```rust
m1 = (a1*x+b1) mod n
m2 = (a2*x+b2) mod n
m1^e mod n == c && m2^e mod n == related_c
```
返回 `Solution::new_m(x)`。GCD 遇到不可逆首项系数时返回 `Unsupported`，不产生伪解。
- [ ] **Step 4: 注册、CLI 和文档**
注册 `franklin_reiter`，元数据为 `&["n", "e", "c", "related_c+related_a1+related_b1+related_a2+related_b2"]`。
CLI 增加五个参数并加入 `has_direct_input`。README 明确 `related_c` 不复用 `c2`，增加固定示例和 `e<=257` 限制。`tests/cli.rs` 断言帮助包含全部参数，JSON 列表包含攻击。
- [ ] **Step 5: Green 与回归**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked'
Expected: 全部通过。
### Task 8: 全量验证、文档定稿和远程工作流门禁
**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-11-26-advanced-rsa-attacks-design.md`
- Modify: `tests/cli.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/windows-release.yml`
**Interfaces:**
- Consumes: Task 1–7 的全部攻击和接口。
- Produces: 最终能力状态、完整测试证据和 Windows 工作流验证记录。
- [ ] **Step 1: 写最终接口契约测试**
```rust
#[test]
fn all_advanced_attacks_are_listed_with_parameters() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let details = report["attack_details"].as_array().unwrap();
    for name in [
        "coppersmith_factor", "coppersmith_message", "partial_d_msb",
        "boneh_durfee", "franklin_reiter",
    ] {
        assert!(details.iter().any(|a| a["name"] == name), "missing {name}");
    }
}
#[test]
fn advanced_help_is_chinese_and_complete() {
    let output = run_bin(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--search-budget", "--m-known", "--m-unknown-bits",
        "--d-known-msb", "--d-unknown-bits", "--related-c",
        "--related-a1", "--related-b1", "--related-a2", "--related-b2",
    ] {
        assert!(stdout.contains(flag), "missing {flag}");
    }
}
```
- [ ] **Step 2: 运行格式、Clippy、测试和 doc-test**
Run: wsl.exe -d Kali -- bash -lc 'cd /mnt/e/Snow/Desktop/Tools_CTF/rascracker && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo fmt --all -- --check && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo clippy --all-targets --all-features --locked -- -D warnings && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --all-features --locked && CARGO_HOME=/tmp/rsacracker-cargo CARGO_TARGET_DIR=/tmp/rsacracker-target cargo test --doc --all-features --locked'
若 WSL 缺少 `rustfmt` 或 `clippy`，使用本机 `C:/Users/Admin/.cargo/bin/rustfmt.exe` 检查修改文件，并在结果中明确记录 Clippy 由公开工作流验证；不得把未执行的命令写成通过。
- [ ] **Step 3: 更新 CI 冒烟测试**
在 `.github/workflows/ci.yml` 和 `windows-release.yml` 的 Windows 冒烟步骤增加：
```powershell
.\rsacracker.exe --list --json | Out-File -Encoding utf8 list.json
$list = Get-Content list.json -Raw | ConvertFrom-Json
$required = @("coppersmith_factor", "coppersmith_message", "partial_d_msb", "boneh_durfee", "franklin_reiter")
foreach ($name in $required) {
    if ($list.attacks -notcontains $name) { throw "missing attack: $name" }
}
.\rsacracker.exe --help | Out-File -Encoding utf8 help.txt
if (-not (Select-String -Path help.txt -Pattern "--m-known" -Quiet)) { throw "missing advanced help" }
```
保持现有 EXE、DLL、`data.txt`、`run.bat` 和 ZIP 冒烟测试。
- [ ] **Step 4: 定稿 README 和设计状态**
README 必须满足：
- 五类攻击均出现在题型矩阵，并标注实际保守条件。
- raw 字段表包含全部新字段。
- 中文帮助快照从真实 `--help` 输出重新生成。
- 每个攻击至少有一个可复制的 raw 或 CLI 示例。
- “设计中，尚不可用”只保留 GUI。
- 明确 `search_budget`、取消、`Unsupported`、`BudgetExceeded` 和 `e<=257`。
- 记录最终测试数量，不继续写旧的 217 作为当前总数。
设计文档第 1 节状态改为“已实现”，保留原设计边界和限制，并记录最终验证日期与测试数量。
- [ ] **Step 5: 全量工作区核验**
Run: C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command "Set-Location -LiteralPath 'e:\Snow\Desktop\Tools_CTF\rascracker'; git diff --check; git status --short; git -c core.quotepath=false diff --stat"
Expected: 无空白错误；只包含本计划预期文件；不包含构建产物、缓存或临时文件。
- [ ] **Step 6: 远程工作流门禁**
只有用户明确授权提交和推送后，才执行提交、推送当前功能分支和公开 GitHub Actions 验证。推送前再次核对远程地址与分支，不强制推送、不合并 `main`、不发布 Release。使用：
```bash
gh run list --repo wakait/CryptoKiller-RsaSoha --limit 5
gh run watch --repo wakait/CryptoKiller-RsaSoha
Expected: `ci.yml` 与 `windows-release.yml` 均成功；把运行 URL、结论和失败日志写入最终交付说明。未获得推送授权时，本步骤保持未执行，不宣称云端验证完成。

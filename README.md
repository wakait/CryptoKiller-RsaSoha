# CryptoKiller RsaSoha

[![Windows Release](https://github.com/wakait/CryptoKiller-RsaSoha/actions/workflows/windows-release.yml/badge.svg)](https://github.com/wakait/CryptoKiller-RsaSoha/actions/workflows/windows-release.yml)
[![CI](https://github.com/wakait/CryptoKiller-RsaSoha/actions/workflows/ci.yml/badge.svg)](https://github.com/wakait/CryptoKiller-RsaSoha/actions/workflows/ci.yml)

基于 [skyf0l/RsaCracker 0.9.2](https://github.com/skyf0l/RsaCracker/tree/v9.2.0) 的 Windows RSA CTF 工具发行项目。保留上游 RSA、X509、OpenSSH、PKCS#12、PKCS#7 和 CSR 支持，并增加默认 `data.txt` 输入、JSON 接口、明确退出码和 Windows 自动打包。

> 仅用于授权的 CTF、教学实验和安全研究。不要用于未经授权的系统或数据。

## Windows 直接使用

从 [Releases](https://github.com/wakait/CryptoKiller-RsaSoha/releases) 下载 `rsacracker-windows-x86_64.zip`，解压到不含空格的路径。

发布包已包含 OpenSSL、GMP、MPFR 和 GCC 运行库，正常无需安装 Windows SDK 或 OpenSSL，也无需配置 `PATH`。

1. 用文本编辑器修改包内 `data.txt`。
2. 双击 `run.bat`。
3. 或打开 PowerShell / CMD：

```powershell
.\rsacracker.exe --json
```

等价的显式写法：

```powershell
.\rsacracker.exe --raw data.txt
.\rsacracker.exe --input data.txt --json
.\rsacracker.exe -r data.txt --attack leaked_pq --threads 4
```

`run.bat` 默认使用 JSON 输出并保留程序退出码；它会暂停窗口以便查看结果。

## data.txt 格式

每行一个 `字段 = 值`，也支持 `字段: 值`。空行和以 `#` 或 `//` 开头的整行注释会被忽略。

```text
# 已知 p、q 时可以不写 n，程序自动计算 n = p * q、phi = (p-1)(q-1)
p = 170141183460469231731687303715884105727
q = 162259276829213363391578010288127
e = 65537
c = 21276652172097553670859187083144524567044111056787806718560215689585764
```

| 字段 | 含义 |
| --- | --- |
| `n` | RSA 模数；可由完整的 `p * q` 推导 |
| `e` | 公钥指数，默认 `65537` |
| `search_budget` | 本次调用共享的纯枚举候选预算，默认 `2^28`；`0` 禁用纯枚举 |
| `c` | 密文/待解密整数 |
| `m_known` | 明文 `m` 的已知高位，例如 `m = m_known * 2^u + x` 中的 `m_known` |
| `m_unknown_bits` | 明文 `m` 的未知低位比特数 `u`；必须与 `m_known` 同时填写，且不超过 `n` 的有效比特数 |
| `related_c` | Franklin–Reiter 第二组密文；五个 `related_*` 字段必须同时填写或同时省略，不复用多密钥字段 `c2` |
| `related_a1` / `related_b1` | 第一组仿射关系 `m1 = related_a1*x + related_b1` 的斜率与截距 |
| `related_a2` / `related_b2` | 第二组仿射关系 `m2 = related_a2*x + related_b2` 的斜率与截距 |
| `p`、`q` | 两个素因子；可填完整整数或 `?` / `...` 通配符 |
| `partial_p`、`partial_q` | 显式的部分素数，写法与 `p` / `q` 通配符相同 |
| `d` | 完整私钥指数；兼容旧用法，在 `partial_d` 攻击中也可填已知 LSB |
| `partial_d` | 私钥指数 `d` 的已知低位（LSB） |
| `partial_d_bits` | `partial_d` 的有效比特数；省略时按实际有效比特计算 |
| `d_known_msb` | 私钥指数 `d` 的已知高位，满足 `d = d_known_msb * 2^u + x` |
| `d_unknown_bits` | `d` 的未知低位比特数 `u`；必须与 `d_known_msb` 同时填写，且不超过 `n` 的有效比特数 |
| `phi` | 欧拉函数 `(p-1)(q-1)`；已知完整 `p/q` 时自动推导 |
| `dp` / `dmp1` | `d mod (p-1)` |
| `dq` / `dmq1` | `d mod (q-1)` |
| `qinv` / `iqmp` | `q^-1 mod p` |
| `pinv` / `ipmq` | `p^-1 mod q` |
| `sum_pq` | `p + q` |
| `diff_pq` | `p - q` |

多密钥题目可使用 `n1/e1/c1`、`n2/e2/c2` 等索引字段，索引支持多位数。若没有非索引的 `n/e/c`，最小索引的密钥会自动提升为主密钥，其余密钥按索引顺序保留。

数值支持十进制、`0x` 十六进制、`0b` 二进制、`0o` 八进制和 `b64` Base64 大端整数。raw 与 CLI 的 `p/q` 均支持部分素数通配符，例如 `0x3d??`（已知高位）、`0x...35`（已知低位）；`?` 与 `...` 不能混用。未知字段或非法值会返回输入错误，不会静默忽略。

## 常见 RSA 题型与参数矩阵

下表列出本工具已覆盖的常见 CTF 类型。`--list` 会显示每个攻击的名称、类型和所需参数；JSON 的 `attack_details` 还提供速度。元数据中 `|` 表示二选一，`+` 表示同时需要。

| 题型 | 已知条件 / 填写字段 | 推荐攻击 |
| --- | --- | --- |
| 已知一个或两个素因子 | `p+q`、`n+p` 或 `n+q` | `leaked_pq` |
| 已知完整私钥指数 | `n`、`e`、`d`；有 `c` 时可恢复私钥并解密 | `known_d` |
| 已知欧拉函数 | `n`、`e`、`phi` | `known_phi` |
| 泄露单个 CRT 指数 | `n`、`e`、`dp` 或 `dq` | `leaked_crt_exponent` |
| 泄露 CRT 指数与系数 | `e`、`dp`、`dq`、`qinv` 或 `pinv` | `leaked_crt_exponents` |
| 泄露两个 CRT 系数 | `e`、`qinv`、`pinv`，以及 `phi` 或 `d` | `leaked_crt_coefficient` |
| 已知 `p+q` 或 `p-q` | `n`、`e`、`sum_pq` 或 `diff_pq` | `sum_pq` / `diff_pq` |
| 已知素因子部分高位或低位 | `n`、`e`、`p/q` 通配符或 `partial_p/partial_q` | `partial_prime` |
| 已知素因子部分高位且满足 `R^4 < n` | `n`、`e`、`partial_p/partial_q` 或 `p/q` 高位通配符 | `coppersmith_factor` |
| 已知私钥指数低位 | `n`、`e`、`partial_d`、`partial_d_bits` | `partial_d` |
| 已知私钥指数高位、低位未知 | `n`、`e`、`d_known_msb`、`d_unknown_bits` | `partial_d_msb` |
| 已知明文高位、低位未知 | `n`、`e`、`c`、`m_known`、`m_unknown_bits` | `coppersmith_message` |
| 同模数同指数的双仿射相关明文 | `n`、`e`、`c`、`related_c`、`related_a1/b1/a2/b2` | `franklin_reiter` |
| Wiener 小私钥指数 | `n`、`e` | `wiener` |
| Boneh–Durfee 小私钥指数 | `n`、`e`；需要平衡素因子与素数 `e` | `boneh_durfee`（实验性：有界回退与格基整数恢复均有夹具验证） |
| 小公钥指数 / 明文未取模 | `n`、`e`、`c` | `small_e` / `cube_root` |
| 密文与模数有公共因子 | `n`、`e`、`c` | `comfact_cn` |
| 同一模数、不同指数加密同一明文 | 两组 `n/e/c`，其中 `n` 相同且指数互素 | `common_modulus` |
| Håstad 广播攻击 | 至少 `e` 组不同模数，指数相同且模数两两互素 | `hastad_broadcast` |
| 多模数公共素因子 | 至少两个 `n` | `common_factor` |
| 素数模数 | `n` 为素数，填写 `e`、`c` | `prime_modulus` |
| 素数模数二次剩余 | `n` 为素数，`e = 2`，填写 `c` | `cipolla` |
| 仅知模数的分解题 | `n`，可选 `e`；适用 Fermat、Pollard、ECM 等 | `--list` 中的分解攻击 |

### 能力状态与推进路线

能力以当前源码、自动化测试和 `--list` 输出为准，不以路线图代替实现。

- **已实现**：上表列出的常见 RSA 题型、raw/CLI 参数填写、多密钥路由、中文帮助、JSON 报告和 Windows 自动打包。五类高级攻击均已注册并有自动化夹具：`coppersmith_factor`、`coppersmith_message`、`partial_d_msb`、`boneh_durfee`、`franklin_reiter`。`boneh_durfee` 仍是实验性入口：小实例有界回退及 `Y > 2047` 的 LLL/整数 resultant 恢复均有固定夹具验证，但不承诺覆盖全部理论边界。
- **数学模块**：精确整数/有理数多项式与 LLL 已实现；部分素数高位的 Coppersmith 攻击已接入 `coppersmith_factor`，并由 `partial_prime` 优先尝试；已知明文高位的 Coppersmith 攻击已接入 `coppersmith_message`；已知私钥指数高位的整数同余/区间攻击已接入 `partial_d_msb`；双仿射相关明文的 Franklin–Reiter 攻击已接入 `franklin_reiter`；`boneh_durfee` 已注册为实验性入口，两条恢复路径均有自动化夹具验证。其他高级攻击仍待接入。
- **Coppersmith 条件**：部分素数高位使用 `f(x)=p_known*R+x`、`X=R`、`beta=1/2` 的精确格基恢复，保守条件为 `R^4 < n`；不满足条件时返回 `Unsupported`，随后 `partial_prime` 才回退到有界枚举。已知明文高位使用 `f(x)=(m_known*2^u+x)^e-c mod n`、`X=2^u`、`beta=1`；`e > 257`、`X^e >= n` 或最小格维超过 64 时返回 `Unsupported`。当 `2^u <= 4096` 时，`coppersmith_message` 先确定性穷举未知低位，并对每个候选执行完整的 `m^e mod n = c` 验证；其余情况使用 LLL。两种 Coppersmith 攻击都不消耗候选预算，`search_budget=0` 时仍可恢复满足条件的已知高位；`coppersmith_message` **恢复明文，不承诺同时分解 `n`**。
- **部分 `d` 高位条件**：`partial_d_msb` 对每个 `k` 的不超过 1024 个候选使用共享预算枚举；大区间提取较大素因子的公共高位，仅在 `R^4 < n` 时调用 Coppersmith 因子助手且不消耗候选预算，否则返回 `Unsupported`。已知素因子低位仍只走枚举，零预算返回 `BudgetExceeded`。
- **Boneh–Durfee 条件**：理论条件为 `d < n^0.292`，当前格基草案采用保守的 `d < n^0.25` 目标并要求素因子平衡；公开指数 `e` 必须为素数，合数返回 `Unsupported`。小实例回退仅在 `Y = floor(sqrt(n))+1 <= 2047` 时启用，枚举完整区间 `[-Y,Y]`，并在枚举前一次性预留 `2Y+1` 个共享候选（最多 4095 个）；因此该回退在 `search_budget=0` 时返回 `BudgetExceeded`，不会零预算成功。`Y > 2047` 时走 LLL 路径：先直接尝试约化基前两行，再按固定上限扫描 16 个行对的整数 resultant；零/常数 resultant 会跳过，不进行全行对扫描。resultant 不模 `e`，使用精确 `integer_roots` 分别恢复有界 `y` 和特化后的 `x`，因此格基路径没有有限域模数或 `u32` 指数限制。已验证夹具为 `p=2003,q=2111,n=4228333,e=2816147,d=3,k=2,Y=2057`，扫描在第 `(0,14)` 行对得到精确根 `y=-2057`；该路径不消耗候选预算，`search_budget=0` 仍成功。有限域根恢复只用于上述小实例有界回退；该回退当前要求素数模数及 Berlekamp 指数可由 `u32` 表示，超出范围返回 `Unsupported`。
- **Franklin–Reiter 条件**：要求五个 `related_*` 字段同时存在、关系矩阵行列式模 `n` 可逆且 `e <= 257`；两个仿射幂多项式必须得到线性首一 GCD。常数 GCD 返回 `NotFound`，非线性 GCD、行列式或 GCD 运算中的首项系数不可逆时返回 `Unsupported`，不会在模合数环上直接取非线性多项式根。候选必须同时通过两个密文方程验证；该攻击恢复 `x`，不承诺分解 `n`，也不消耗候选预算。
- **预算与取消**：默认共享预算为 `2^28` 个候选，可通过 raw `search_budget` 或 CLI `--search-budget` 调整；`0` 表示禁用纯枚举。搜索空间超过剩余预算时返回 `BudgetExceeded`，任一攻击成功后协作取消其余攻击。库调用方可通过 `AttackControl::cancel` 请求取消，攻击返回 `Cancelled`。
- **设计中，尚不可用**：图形界面（GUI）。

实施顺序固定为：**先高级攻击，后 GUI**。高级攻击计划采用纯 Rust 整数格与多项式模块，不要求 Sage、Python 或 fplll。

高级攻击的[设计文档](docs/superpowers/specs/2026-11-26-advanced-rsa-attacks-design.md)与[实施计划](docs/superpowers/plans/2026-11-26-advanced-rsa-attacks.md)已固化。计划按八个可测试里程碑推进；每个里程碑完成后，本章节的能力状态、字段表、示例和限制会同步更新，不以路线图代替已实现能力。

#### 里程碑同步验收规则

每完成一个攻击或接口里程碑，必须在同一轮变更中同步更新：

1. 攻击实现、注册表和 `--list` / `attack_details` 元数据；
2. CLI 中文帮助、raw 字段表、参数矩阵与可用示例；
3. 单元测试、CLI/raw/JSON 回归测试和边界测试；
4. README 的能力状态，只有通过测试的能力才能从“设计中”移入“已实现”；
5. 完整测试、格式检查、Clippy 和公开 Windows 工作流结果。

未满足上述同步要求的里程碑不标记为完成。

### 填写示例

已知 `d` 的低 8 bit 为 `193`：

```text
n = 3233
e = 17
c = 2557
partial_d = 193
partial_d_bits = 8
```

```powershell
.\rsacracker.exe --raw data.txt --attack partial_d --json
.\rsacracker.exe -n 3233 -e 17 -c 2557 --partial-d 193 --partial-d-bits 8 --attack partial_d
```

已知 `d` 的高 8 位为 `172`、低 4 位未知，即 `d = 172 * 2^4 + x`，其中 `0 <= x < 2^4`：

```text
n = 3233
e = 17
c = 2557
d_known_msb = 172
d_unknown_bits = 4
```

```powershell
.\rsacracker.exe --raw data.txt --attack partial_d_msb --json
.\rsacracker.exe -n 3233 -e 17 -c 2557 --d-known-msb 172 --d-unknown-bits 4 --attack partial_d_msb --json
```

固定向量恢复 `p = 53`、`q = 61`、`d = 2753` 和明文 `42`。攻击按 `ed - 1 = kφ(n)` 推导整数同余与 `p+q` 区间；所有候选最终验证 `p*q = n`、双方素性、`ed mod phi = 1`、指定 `d` 前缀区间和 `PrivateKey::from_p_q` 重建，不返回伪解。

共享预算在并发攻击和 `partial_p` / `partial_q` 的多次尝试之间原子预留，不会超支；CLI 显式值优先于 raw 值，未指定 CLI 值时保留 raw 自定义预算。库接口 `run_specific_attacks_with_control` 可传入共享 `AttackControl`；预算耗尽对应 `Error::BudgetExceeded`，CLI 保持“输入有效但无攻击成功”的退出码 `1`。

仅知道 `p` 的高位或 `q` 的低位：

```text
n = 3233
e = 17
p = 0x3d??
q = 0x...35
```

可将本次纯枚举预算限制为 100 万个候选；设为 `0` 可禁用纯枚举：

```powershell
.\rsacracker.exe --raw data.txt --attack partial_prime --search-budget 1048576 --json
.\rsacracker.exe --raw data.txt --attack partial_prime --search-budget 0 --json
```

已知 `m = 964 * 2^7 + x`，其中 `0 <= x < 2^7`，未知低 7 位，且密文由 `e = 5` 生成：

```text
n = 1000036000099
e = 5
c = 819449521559
m_known = 964
m_unknown_bits = 7
```

```powershell
.\rsacracker.exe --raw data.txt --attack coppersmith_message --search-budget 0 --threads 1 --json
.\rsacracker.exe -n 1000036000099 -e 5 -c 819449521559 --m-known 964 --m-unknown-bits 7 --attack coppersmith_message --json
```

固定向量恢复 `m = 123456`；该攻击恢复明文，不承诺同时分解 `n`，因此成功报告不包含私钥。

同模数、同指数 `e = 3`，两个明文满足 `m1 = 2*x + 3`、`m2 = 3*x + 5`：

```text
n = 3233
e = 3
c = 1680
related_c = 1411
related_a1 = 2
related_b1 = 3
related_a2 = 3
related_b2 = 5
```

```powershell
.\rsacracker.exe --raw data.txt --attack franklin_reiter --search-budget 0 --threads 1 --json
.\rsacracker.exe -n 3233 -e 3 -c 1680 --related-c 1411 --related-a1 2 --related-b1 3 --related-a2 3 --related-b2 5 --attack franklin_reiter --json
```

固定向量恢复 `x = 7`（即 `m1 = 17`、`m2 = 26`），两个密文分别为 `17^3 mod 3233 = 1680` 和 `26^3 mod 3233 = 1411`。`related_c` 是独立字段，不与多密钥输入中的 `c2` 混用。

Boneh–Durfee 小实例回退示例（`n=3233`、`e=1783`、`d=7`）：

```text
n = 3233
e = 1783
```

```powershell
.\rsacracker.exe --raw data.txt --attack boneh_durfee --threads 1 --json
.\rsacracker.exe -n 3233 -e 1783 --attack boneh_durfee --json
```

固定向量恢复 `p = 53`、`q = 61`、`d = 7`。该例走 `Y <= 2047` 的有界回退，会按 `2Y+1` 预留共享候选预算；`--search-budget 0` 时返回 `BudgetExceeded`。

当已知部分为 `p`/`q` 的高位、低位未知且满足 `R^4 < n` 时，也可直接选择 `coppersmith_factor`；它在零枚举预算下仍执行格基恢复，并对候选执行整除、双方素性和私钥重建验证：

```text
n = 27606985387162255149739023449107931668458716142620601169954803000803329
e = 65537
p = 0x7fffffffffffffffffffffffffff????
```

```powershell
.\rsacracker.exe --raw data.txt --attack coppersmith_factor --search-budget 0 --json
.\rsacracker.exe -n 27606985387162255149739023449107931668458716142620601169954803000803329 -p 0x7fffffffffffffffffffffffffff???? --attack coppersmith_factor --search-budget 0 --json
```

固定向量恢复 `p = 170141183460469231731687303715884105727`、`q = 162259276829213363391578010288127`。若已知的是低位，则继续使用 `partial_prime` 和纯枚举预算。

同一模数使用两个指数加密同一明文：

```text
n1 = 3233
e1 = 17
c1 = 2557
n2 = 3233
e2 = 5
c2 = 440
```

### 错误、预算与取消语义

- `search_budget`（CLI `--search-budget`）默认 `2^28`，只约束纯枚举候选；`0` 禁用纯枚举。Coppersmith 的小 bound 确定性路径和 LLL 路径、Franklin–Reiter、Boneh–Durfee 的 LLL 路径均不消耗该预算。
- `BudgetExceeded` 表示纯枚举搜索空间超过剩余共享预算；CLI 在输入有效但没有攻击成功时保持退出码 `1`。
- `Unsupported` 表示输入超出保守数学条件或资源上限，例如 Coppersmith 的 `R^4 < n`、`e <= 257`、格维上限，或 Boneh–Durfee 的合数公开指数。
- `Cancelled` 表示收到协作取消信号；库调用方可调用 `AttackControl::cancel`，任一攻击成功后调度器也会取消其余攻击。
- JSON 协议和退出码 `0/1/2` 不变：`0` 表示成功或帮助/列表命令成功，`1` 表示输入有效但无攻击成功，`2` 表示参数、文件、数据格式或运行时错误。

### 输入优先级

1. 显式 `--raw` / `--input` / `-r`；
2. 管道/stdin 中的非空文本；
3. 没有直接提供密钥参数时，读取当前目录 `data.txt`；
4. 没有可用输入时返回输入错误。

`--help`、`--version` 和 `--list` 不会触发默认解题。

## 命令行参数

`-h` 与 `--help` 均显示中文帮助：

```text
面向 CTF 的 RSA 破解工具，支持 RSA、X509、OPENSSH、PKCS#12、PKCS#7 和 CSR（PEM/DER）密钥。

用法: rsacracker [选项]

选项:
  -r, --raw <RAW>
          从 raw 文件读取参数
      --json
          输出可供机器读取的 JSON 报告。
  -c, --cipher <CIPHER>
          待解密的密文整数；可多次指定以进行多密钥攻击。
      --m-known <M_KNOWN>
          明文 m 的已知高位（十进制或带前缀整数）。
      --m-unknown-bits <M_UNKNOWN_BITS>
          明文 m 的未知低位比特数，必须与 --m-known 同时提供。
      --related-c <RELATED_C>
          第二组密文，用于 related-message 攻击；不复用多密钥的 c2。
      --related-a1 <RELATED_A1>
          第一组仿射关系的斜率 a1：m1 = a1*x + b1。
      --related-b1 <RELATED_B1>
          第一组仿射关系的截距 b1。
      --related-a2 <RELATED_A2>
          第二组仿射关系的斜率 a2：m2 = a2*x + b2。
      --related-b2 <RELATED_B2>
          第二组仿射关系的截距 b2。
  -f, --cipherfile <CIPHERFILE>
          密文文件；可多次指定以进行多密钥攻击。
  -o, --outfile <OUTFILE>
          将解密结果写入文件；多个结果将使用 _1、_2 等后缀。
  -n <N>
          RSA 模数；可多次指定以进行多密钥攻击。
  -e <E>
          公钥指数，默认 65537；可多次指定以进行多密钥攻击。
  -p <P>
          素数 p；支持通配符，例如 0xDEADBEEF????、10737418??、0x...C0FFEE。
  -q <Q>
          素数 q；支持通配符，例如 0x????C0FFEE、??741827、0x...C0FFEE。
  -d <D>
          私钥指数。
      --partial-d <PARTIAL_D>
          私钥指数 d 的已知低位（LSB），用于 partial_d 攻击。
      --partial-d-bits <PARTIAL_D_BITS>
          partial_d 的有效比特数；省略时按 partial_d 的实际比特数计算。
      --d-known-msb <D_KNOWN_MSB>
          私钥指数 d 的已知高位（MSB），用于 partial_d_msb 攻击。
      --d-unknown-bits <D_UNKNOWN_BITS>
          d 的未知低位比特数，必须与 --d-known-msb 同时提供。
      --phi <PHI>
          n 的欧拉函数 phi，即 (p-1)(q-1)。
      --dp <DP>
          CRT 指数 dP（别名 dmp1）：d mod (p-1)。
      --dq <DQ>
          CRT 指数 dQ（别名 dmq1）：d mod (q-1)。
      --qinv <QINV>
          CRT 系数 qInv（别名 iqmp）：q^-1 mod p。
      --pinv <PINV>
          CRT 系数 pInv（别名 ipmq）：p^-1 mod q。
      --sum-pq <SUM_PQ>
          两个素因子 p 与 q 的和。
      --diff-pq <DIFF_PQ>
          两个素因子 p 与 q 的差。
      --dlog
          离散对数攻击：RSA 公式中的 c 与 e 互换时使用（e^c mod n）。
  -k, --key <KEY>
          公钥或私钥文件，支持 RSA、X509、OPENSSH、PKCS#12、PKCS#7、CSR 的 PEM/DER 格式；可多次指定。
      --password <PASSWORD>
          加密私钥的密码或口令。
      --public
          输出 PEM 格式的公钥。
      --private
          输出 PEM 格式的私钥。
      --addpassword <ADDPASSWORD>
          为输出的私钥添加密码或口令。
      --showinputs
          显示全部输入参数。
      --dump
          输出 RSA 私钥变量 n、e、p、q 和 d。
      --dumpext
          输出扩展 RSA 私钥变量 n、e、p、q、d、dP、dQ、pInv 和 qInv。
      --factors
          输出 n 的全部素因子。
      --bits
          在显示的数值后添加比特长度。
  -t, --threads <THREADS>
          使用的线程数，默认使用 CPU 核心数。
      --search-budget <SEARCH_BUDGET>
          本次调用共享的纯枚举候选预算；默认 2^28，0 表示禁用纯枚举。
  -a, --attack <ATTACK>
          指定要运行的攻击，默认全部；可用逗号分隔多个攻击。
      --exclude <EXCLUDE>
          指定要排除的攻击，默认不排除；可用逗号分隔多个攻击。
      --list
          列出全部可用攻击。
  -h, --help
          显示帮助信息
  -V, --version
          显示版本信息
```

攻击名称请以 `--list` 输出为准，其中会同时列出所需参数。已知 `p/q` 时可使用 `--attack leaked_pq`；已知完整 `d` 时使用 `known_d`；已知 `d` 的低位时使用 `partial_d`；已知 `d` 的高位时使用 `partial_d_msb`。不指定 `--attack` 会运行全部攻击，大规模模数可能耗时较长。

## 供其他程序调用

推荐同时使用 `--json` 和 `RSACRACKER_DISABLE_UPDATE=1`，避免程序进行更新检查。JSON 模式不会向 stdout 混入人类可读文本；错误信息可以通过 `error` 字段和退出码判断。

成功示例：

```json
{
  "version": "0.9.2",
  "success": true,
  "attack": "leaked_pq",
  "elapsed_seconds": 0.003,
  "message": {
    "integer": "10962199670272155981934654169811811191204889316897352061",
    "hex": "0x727361637261636b65727b77696e646f77735f636c697d",
    "string": "rsacracker{windows_cli}",
    "bytes": [114, 115, 97, 99, 114, 97, 99, 107, 101, 114, 123, 119, 105, 110, 100, 111, 119, 115, 95, 99, 108, 105, 125]
  }
}
```

实际输出还取决于 `--dump`、`--dumpext`、`--factors`、`--private` 等模式；多个候选明文位于 `messages` 数组。`--list --json` 保留 `attacks` 名称数组，并通过 `attack_details` 返回 `name`、`kind`、`speed`、`required_parameters`；`--public --json` 在 `public_key` 字段返回 PEM 文本。

### PowerShell

```powershell
$env:RSACRACKER_DISABLE_UPDATE = "1"
$process = Start-Process -FilePath ".\rsacracker.exe" `
  -ArgumentList "--raw", "data.txt", "--json", "--threads", "4" `
  -NoNewWindow -Wait -PassThru -RedirectStandardOutput "result.json"
$report = Get-Content "result.json" -Raw | ConvertFrom-Json
$report.message.string
$process.ExitCode
```

### Python

```python
import json
import subprocess

process = subprocess.run(
    [r".\rsacracker.exe", "--raw", "data.txt", "--json"],
    capture_output=True,
    text=True,
    check=False,
)
report = json.loads(process.stdout)
if process.returncode == 0 and report["success"]:
    print(report["message"]["string"])
else:
    print(report.get("error"), process.returncode)
```

### 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功，或成功执行 `--help` / `--version` / `--list` |
| `1` | 输入有效，但没有攻击成功 |
| `2` | 参数、文件、数据格式或运行时错误 |

## 从源码构建

Windows 需要 GNU 工具链，因为 `rug` 依赖 GMP/MPFR，并启用了 `rational` 特性以支持精确多项式与 LLL 运算。直接使用默认 MSVC 执行 `cargo build` 会在 `gmp-mpfr-sys` 阶段失败，这是已知限制。

在 GitHub Actions 中，工作流使用 Windows runner、MSYS2 UCRT64，并将 Cargo 与构建目录放到 D 盘。每次推送和 Pull Request 都会执行格式、Clippy、未过滤完整测试（含 doc-tests）、Windows 高级攻击冒烟测试、Release 构建和 ZIP 打包。

本地 MSYS2 UCRT64 手动构建示例：

```bash
pacman -S --needed base-devel pacman-mirrors diffutils m4 make pkgconf zip
pacboy -S --needed gcc:p rust:p openssl:p
export CARGO_HOME=E:/rsacracker-cargo
export CARGO_TARGET_DIR=E:/rsacracker-target
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo test --doc --all-features --locked
cargo build --release --locked --target x86_64-pc-windows-gnu
```

2026-11-28 本地未过滤验证：`cargo test --all-features --locked` 共 **381 passed**（含单元、集成、CLI 与 CTF 回归），`cargo test --doc --all-features --locked` 为 **0 passed**，`cargo fmt --all -- --check` 通过。Windows Clippy 因本机缺少 GNU target/MSYS2 工具链未完成；公开 Windows 工作流的结果以远端 Actions 运行记录为准。

## 故障排查

- **缺少 DLL**：优先重新下载完整 Release ZIP，不要只复制 EXE。所有 DLL 应与 EXE 位于同一目录。
- **默认没有读取题目**：确认运行时的当前目录包含 `data.txt`，或显式传入 `--raw 路径`。
- **提示字段解析失败**：检查字段名、数字格式和通配符位置；未知字段会报错，普通整数不要添加 `...`。
- **不知道填哪个攻击**：运行 `--list` 查看所需参数，或先用 `--showinputs` 检查解析结果。
- **一直运行**：ECM、Pollard Rho 等攻击可能耗时较长；使用 `--threads` 调整并发。
- **纯枚举预算耗尽**：库错误为 `BudgetExceeded`，CLI 返回退出码 `1`；可降低 `--search-budget` 快速失败，设为 `0` 禁用纯枚举，或提供更多已知参数。

## 上游与许可证

本项目源码基线为 `skyf0l/RsaCracker` 的 `v9.2.0` 标签（Cargo 版本 `0.9.2`）。Windows 发行适配、JSON CLI、默认输入和发布工作流在本仓库维护。

遵循上游双许可证：`MIT OR Apache-2.0`。详见 `LICENSE-MIT` 和 `LICENSE-APACHE`。

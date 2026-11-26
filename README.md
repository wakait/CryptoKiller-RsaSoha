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
# 已知 p、q 时可以不写 n，程序自动计算 n = p * q
p = 170141183460469231731687303715884105727
q = 162259276829213363391578010288127
e = 65537
c = 21276652172097553670859187083144524567044111056787806718560215689585764
```

| 字段 | 含义 |
| --- | --- |
| `n` | RSA 模数；可由 `p * q` 推导 |
| `e` | 公钥指数，默认 `65537` |
| `c` | 密文/待解密整数 |
| `p`、`q` | 两个素因子 |
| `d` | 私钥指数 |
| `phi` | 欧拉函数 `(p-1)(q-1)` |
| `dp` / `dmp1` | `d mod (p-1)` |
| `dq` / `dmq1` | `d mod (q-1)` |
| `qinv` / `iqmp` | `q^-1 mod p` |
| `pinv` / `ipmq` | `p^-1 mod q` |
| `sum_pq` | `p + q` |
| `diff_pq` | `p - q` |

多密钥题目可使用 `n1/e1/c1`、`n2/e2/c2` 等索引字段。

数值支持十进制、`0x` 十六进制、`0b` 二进制、`0o` 八进制和 `b64` Base64 大端整数。CLI 的 `-p/-q` 还支持 `?` 和 `...` 部分素数通配符。

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
  -r, --raw <RAW>                  从 raw 文件读取参数
  -c, --cipher <CIPHER>            待解密的密文整数；可多次指定以进行多密钥攻击。
  -f, --cipherfile <CIPHERFILE>    密文文件；可多次指定以进行多密钥攻击。
  -o, --outfile <OUTFILE>          将解密结果写入文件；多个结果将使用 _1、_2 等后缀。
  -n <N>                           RSA 模数；可多次指定以进行多密钥攻击。
  -e <E>                           公钥指数，默认 65537；可多次指定以进行多密钥攻击。
  -p <P>                           素数 p；支持通配符，例如 0xDEADBEEF????、10737418??、0x...C0FFEE。
  -q <Q>                           素数 q；支持通配符，例如 0x????C0FFEE、??741827、0x...C0FFEE。
  -d <D>                           私钥指数。
      --phi <PHI>                  n 的欧拉函数 phi，即 (p-1)(q-1)。
      --dp <DP>                     CRT 指数 dP（别名 dmp1）：d mod (p-1)。
      --dq <DQ>                     CRT 指数 dQ（别名 dmq1）：d mod (q-1)。
      --qinv <QINV>                 CRT 系数 qInv（别名 iqmp）：q^-1 mod p。
      --pinv <PINV>                 CRT 系数 pInv（别名 ipmq）：p^-1 mod q。
      --sum-pq <SUM_PQ>             两个素因子 p 与 q 的和。
      --diff-pq <DIFF_PQ>           两个素因子 p 与 q 的差。
      --dlog                        离散对数攻击：RSA 公式中的 c 与 e 互换时使用（e^c mod n）。
  -k, --key <KEY>                  公钥或私钥文件，支持 RSA、X509、OPENSSH、PKCS#12、PKCS#7、CSR 的 PEM/DER 格式；可多次指定。
      --password <PASSWORD>        加密私钥的密码或口令。
      --public                      输出 PEM 格式的公钥。
      --private                     输出 PEM 格式的私钥。
      --addpassword <ADDPASSWORD>  为输出的私钥添加密码或口令。
      --showinputs                  显示全部输入参数。
      --dump                        输出 RSA 私钥变量 n、e、p、q 和 d。
      --dumpext                     输出扩展 RSA 私钥变量 n、e、p、q、d、dP、dQ、pInv 和 qInv。
      --factors                     输出 n 的全部素因子。
      --bits                        在显示的数值后添加比特长度。
      --json                        输出可供机器读取的 JSON 报告。
  -t, --threads <THREADS>          使用的线程数，默认使用 CPU 核心数。
  -a, --attack <ATTACK>            指定要运行的攻击，默认全部；可用逗号分隔多个攻击。
      --exclude <EXCLUDE>          指定要排除的攻击，默认不排除；可用逗号分隔多个攻击。
      --list                        列出全部可用攻击。
  -h, --help                       显示帮助信息
  -V, --version                    显示版本信息
```

攻击名称请以 `--list` 输出为准。已知 `p/q` 时可使用 `--attack leaked_pq`；已知部分 CRT 指数时可使用 `leaked_crt_exponents`。不指定 `--attack` 会运行全部攻击，大规模模数可能耗时较长。

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

实际输出还取决于 `--dump`、`--dumpext`、`--factors`、`--private` 等模式；多个候选明文位于 `messages` 数组。`--list --json` 在 `attacks` 数组返回攻击名，`--public --json` 在 `public_key` 字段返回 PEM 文本。

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

Windows 需要 GNU 工具链，因为 `rug` 依赖 GMP/MPFR。直接使用默认 MSVC 执行 `cargo build` 会在 `gmp-mpfr-sys` 阶段失败，这是已知限制。

在 GitHub Actions 中，工作流使用 Windows runner、MSYS2 UCRT64，并将 Cargo 与构建目录放到 D 盘。每次推送和 Pull Request 都会执行格式、Clippy、测试、Release 构建、冒烟测试和 ZIP 打包。

本地 MSYS2 UCRT64 手动构建示例：

```bash
pacman -S --needed base-devel pacman-mirrors diffutils m4 make pkgconf zip
pacboy -S --needed gcc:p rust:p openssl:p
export CARGO_HOME=E:/rsacracker-cargo
export CARGO_TARGET_DIR=E:/rsacracker-target
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked --target x86_64-pc-windows-gnu
```

## 故障排查

- **缺少 DLL**：优先重新下载完整 Release ZIP，不要只复制 EXE。所有 DLL 应与 EXE 位于同一目录。
- **默认没有读取题目**：确认运行时的当前目录包含 `data.txt`，或显式传入 `--raw 路径`。
- **提示字段解析失败**：检查数字前是否混入单位、引号或省略号；原始整数不要添加 `...`。
- **没有攻击成功**：先运行 `--showinputs` 检查解析结果，再依据已知条件缩小 `--attack` 范围。
- **一直运行**：ECM、Pollard Rho 等攻击可能耗时较长；使用 `--threads` 调整并发。

## 上游与许可证

本项目源码基线为 `skyf0l/RsaCracker` 的 `v9.2.0` 标签（Cargo 版本 `0.9.2`）。Windows 发行适配、JSON CLI、默认输入和发布工作流在本仓库维护。

遵循上游双许可证：`MIT OR Apache-2.0`。详见 `LICENSE-MIT` 和 `LICENSE-APACHE`。

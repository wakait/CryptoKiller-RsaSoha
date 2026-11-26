use clap::Parser;
use discrete_logarithm::discrete_log_with_factors;
use display_bytes::display_bytes;
use itertools::Itertools;
use rug::{
    integer::{IsPrime, Order},
    Integer,
};
use std::{
    io::{self, IsTerminal, Read, Write},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use rsacracker::{
    integer_to_bytes, integer_to_string, Attack, IntegerArg, KeyEntry, Parameters, PartialPrimeArg,
    ATTACKS,
};
use update_informer::{registry, Check};

#[derive(Debug, Clone)]
struct AttackArg(Arc<dyn Attack + Sync + Send>);

impl std::str::FromStr for AttackArg {
    type Err = String;

    fn from_str(attack: &str) -> Result<Self, Self::Err> {
        ATTACKS
            .iter()
            .find(|a| a.name() == attack)
            .map(|a| Self(a.clone()))
            .ok_or_else(|| format!("Unknown attack: {attack}"))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "面向 CTF 的 RSA 破解工具，支持 RSA、X509、OPENSSH、PKCS#12、PKCS#7 和 CSR（PEM/DER）密钥。",
    override_usage = "rsacracker [选项]",
    disable_help_flag = true,
    disable_version_flag = true,
    help_template = "{about}\n\n用法: {usage}\n\n选项:\n{options}"
)]
// IMPORTANT: When modifying CLI arguments, ALWAYS update the README.md Usage section
// to match the --help output. The README should reflect the actual CLI behavior.
struct Args {
    /// 从 raw 文件读取参数
    #[clap(short, long, alias = "input")]
    raw: Option<String>,
    /// 输出可供机器读取的 JSON 报告。
    #[clap(long)]
    json: bool,
    /// 待解密的密文整数；可多次指定以进行多密钥攻击。
    #[clap(short, long)]
    cipher: Vec<IntegerArg>,
    /// 密文文件；可多次指定以进行多密钥攻击。
    #[clap(short = 'f', long)]
    cipherfile: Vec<std::path::PathBuf>,
    /// 将解密结果写入文件；多个结果将使用 _1、_2 等后缀。
    #[clap(short = 'o', long)]
    outfile: Option<std::path::PathBuf>,
    /// RSA 模数；可多次指定以进行多密钥攻击。
    #[clap(short)]
    n: Vec<IntegerArg>,
    /// 公钥指数，默认 65537；可多次指定以进行多密钥攻击。
    #[clap(short)]
    e: Vec<IntegerArg>,
    /// 素数 p；支持通配符，例如 0xDEADBEEF????、10737418??、0x...C0FFEE。
    #[clap(short)]
    p: Option<PartialPrimeArg>,
    /// 素数 q；支持通配符，例如 0x????C0FFEE、??741827、0x...C0FFEE。
    #[clap(short)]
    q: Option<PartialPrimeArg>,
    /// 私钥指数。
    #[clap(short)]
    d: Option<IntegerArg>,
    /// n 的欧拉函数 phi，即 (p-1)(q-1)。
    #[clap(long)]
    phi: Option<IntegerArg>,
    /// CRT 指数 dP（别名 dmp1）：d mod (p-1)。
    #[clap(long, alias = "dmp1")]
    dp: Option<IntegerArg>,
    /// CRT 指数 dQ（别名 dmq1）：d mod (q-1)。
    #[clap(long, alias = "dmq1")]
    dq: Option<IntegerArg>,
    /// CRT 系数 qInv（别名 iqmp）：q^-1 mod p。
    #[clap(long, alias = "iqmp")]
    qinv: Option<IntegerArg>,
    /// CRT 系数 pInv（别名 ipmq）：p^-1 mod q。
    #[clap(long, alias = "ipmq")]
    pinv: Option<IntegerArg>,
    /// 两个素因子 p 与 q 的和。
    #[clap(long)]
    sum_pq: Option<IntegerArg>,
    /// 两个素因子 p 与 q 的差。
    #[clap(long)]
    diff_pq: Option<IntegerArg>,
    /// 离散对数攻击：RSA 公式中的 c 与 e 互换时使用（e^c mod n）。
    #[clap(long, alias = "dislog")]
    dlog: bool,
    /// 公钥或私钥文件，支持 RSA、X509、OPENSSH、PKCS#12、PKCS#7、CSR 的 PEM/DER 格式；可多次指定。
    #[clap(short, long)]
    key: Vec<String>,
    /// 加密私钥的密码或口令。
    #[clap(long)]
    password: Option<String>,
    /// 输出 PEM 格式的公钥。
    #[clap(long)]
    public: bool,
    /// 输出 PEM 格式的私钥。
    #[clap(long)]
    private: bool,
    /// 为输出的私钥添加密码或口令。
    #[clap(long, requires("private"))]
    addpassword: Option<String>,
    /// 显示全部输入参数。
    #[clap(long)]
    showinputs: bool,
    /// 输出 RSA 私钥变量 n、e、p、q 和 d。
    #[clap(long)]
    dump: bool,
    /// 输出扩展 RSA 私钥变量 n、e、p、q、d、dP、dQ、pInv 和 qInv。
    #[clap(long)]
    dumpext: bool,
    /// 输出 n 的全部素因子。
    #[clap(long)]
    factors: bool,
    /// 在显示的数值后添加比特长度。
    #[clap(long)]
    bits: bool,
    /// 使用的线程数，默认使用 CPU 核心数。
    #[clap(short, long, default_value_t = num_cpus::get())]
    threads: usize,
    /// 指定要运行的攻击，默认全部；可用逗号分隔多个攻击。
    #[clap(
        short,
        long,
        alias = "attacks",
        value_delimiter = ',',
        conflicts_with = "exclude"
    )]
    attack: Option<Vec<AttackArg>>,
    /// 指定要排除的攻击，默认不排除；可用逗号分隔多个攻击。
    #[clap(long, value_delimiter = ',', conflicts_with = "attack")]
    exclude: Option<Vec<AttackArg>>,
    /// 列出全部可用攻击。
    #[clap(long)]
    list: bool,
    #[arg(
        id = "help",
        short = 'h',
        long = "help",
        action = clap::ArgAction::Help,
        help = "显示帮助信息"
    )]
    _help: Option<bool>,
    #[arg(
        id = "version",
        short = 'V',
        long = "version",
        action = clap::ArgAction::Version,
        help = "显示版本信息"
    )]
    _version: Option<bool>,
}

fn display_value(label: &str, value: &Integer, show_bits: bool) {
    if show_bits {
        println!("{} = {} ({} bits)", label, value, value.significant_bits());
    } else {
        println!("{} = {}", label, value);
    }
}

fn display_unciphered_data(uncipher: &Integer) {
    println!("Int = {uncipher}");
    println!("Hex = 0x{uncipher:02x}");
    if let Some(str) = integer_to_string(uncipher) {
        println!("String = \"{str}\"");
    } else {
        println!(
            "Bytes = b\"{}\"",
            display_bytes(&integer_to_bytes(uncipher))
        );
    }
}

fn display_or_output(
    uncipher: &Integer,
    outfile: &Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(outfile) = outfile {
        println!(
            "Write unciphered data to file: {}",
            outfile.to_string_lossy()
        );
        std::fs::write(outfile, integer_to_bytes(uncipher))?;
    } else {
        println!("Unciphered data:");
        display_unciphered_data(uncipher);
    }

    Ok(())
}

/// Add a suffix to the file path, before the extension.
fn suffix_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut path = path.to_path_buf();
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            path.set_file_name(format!("{stem}{suffix}.{ext}"));
            return path;
        }
    }
    // Fallback: append suffix to the entire path
    path.set_file_name(format!("{}{suffix}", path.to_string_lossy()));
    path
}

fn print_json(report: &serde_json::Value) {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    // Reports only contain serializable values created by this program.
    serde_json::to_writer(&mut stdout, report).expect("failed to serialize JSON report");
    writeln!(stdout).expect("failed to write JSON report");
}

fn error_report(error: &str) -> serde_json::Value {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "success": false,
        "error": error,
    })
}

fn main() -> ExitCode {
    let json = std::env::args_os().any(|arg| arg == "--json");
    match run(json) {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            if json {
                print_json(&error_report(&error.to_string()));
            } else {
                eprintln!("Error: {error}");
            }
            ExitCode::from(2)
        }
    }
}

fn run(json: bool) -> Result<i32, Box<dyn std::error::Error>> {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if json {
                print_json(&error_report(&error.to_string()));
            } else {
                error.print().expect("failed to print CLI error");
            }
            return Ok(
                if matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) {
                    0
                } else {
                    2
                },
            );
        }
    };
    let json = json || args.json;
    let pkg_name = env!("CARGO_PKG_NAME");
    let current_version = env!("CARGO_PKG_VERSION");

    // Machine-readable mode must not perform network update checks.
    if !json && std::env::var("RSACRACKER_DISABLE_UPDATE").is_err() {
        let informer = update_informer::new(registry::Crates, pkg_name, current_version)
            .interval(Duration::from_secs(60 * 60));
        if let Ok(Some(new_version)) = informer.check_version() {
            eprintln!(
                "A new release of {pkg_name} is available: v{current_version} -> {new_version}"
            );
            eprintln!("You can update by running: cargo install {pkg_name}\n");
        }
    }

    // List attacks
    if args.list {
        if json {
            print_json(&serde_json::json!({
                "version": current_version,
                "success": true,
                "attacks": ATTACKS.iter().map(|attack| attack.name()).collect::<Vec<_>>(),
            }));
        } else {
            println!("Available attacks:");
            for attack in ATTACKS.iter() {
                println!("  {}", attack.name());
            }
        }
        return Ok(0);
    }

    // Read all cipherfiles into a vector
    let cipherfiles_data: Result<Vec<Integer>, Box<dyn std::error::Error>> = args
        .cipherfile
        .iter()
        .map(|cipher_path| match std::fs::read(cipher_path) {
            Ok(bytes) => Ok(Integer::from_digits(&bytes, Order::Msf)),
            Err(err) => Err(format!("{}: {err}", cipher_path.to_string_lossy()).into()),
        })
        .collect();
    let cipherfiles_data = cipherfiles_data?;

    // Combine -c and -f parameters into a unified cipher list
    // -c parameters come first, then cipherfiles
    let all_ciphers: Vec<Integer> = args
        .cipher
        .iter()
        .map(|c| c.0.clone())
        .chain(cipherfiles_data)
        .collect();

    // Read cipher (first from the combined list)
    let c = all_ciphers.first().cloned();

    // Explicit raw input wins, followed by non-empty stdin and data.txt.
    let mut stdin = io::stdin();
    let mut piped = String::new();
    if args.raw.is_none() && !stdin.is_terminal() {
        stdin.read_to_string(&mut piped)?;
    }
    let has_direct_input = !args.n.is_empty()
        || !args.e.is_empty()
        || !args.cipher.is_empty()
        || !args.cipherfile.is_empty()
        || args.p.is_some()
        || args.q.is_some()
        || args.d.is_some()
        || args.phi.is_some()
        || args.dp.is_some()
        || args.dq.is_some()
        || args.qinv.is_some()
        || args.pinv.is_some()
        || args.sum_pq.is_some()
        || args.diff_pq.is_some()
        || !args.key.is_empty();
    let raw = if let Some(path) = args.raw.as_ref() {
        Some(std::fs::read_to_string(path)?)
    } else if !piped.trim().is_empty() {
        Some(piped)
    } else if !has_direct_input && std::path::Path::new("data.txt").is_file() {
        Some(std::fs::read_to_string("data.txt")?)
    } else {
        None
    };
    let mut params = match raw {
        Some(raw) => {
            Parameters::try_from_raw(&raw).map_err(|error| format!("Invalid raw input: {error}"))?
        }
        None => Parameters::default(),
    };

    // Build parameters
    params += Parameters {
        c,
        n: args.n.first().map(|n| n.0.clone()),
        e: args
            .e
            .first()
            .map(|e| e.0.clone())
            .unwrap_or_else(|| Integer::from(65537)),
        p: args.p.as_ref().and_then(|p| p.0.full().cloned()),
        q: args.q.as_ref().and_then(|q| q.0.full().cloned()),
        d: args.d.map(|n| n.0),
        phi: args.phi.map(|n| n.0),
        dp: args.dp.map(|n| n.0),
        dq: args.dq.map(|n| n.0),
        qinv: args.qinv.map(|n| n.0),
        pinv: args.pinv.map(|n| n.0),
        sum_pq: args.sum_pq.map(|n| n.0),
        diff_pq: args.diff_pq.map(|n| n.0),
        partial_p: args.p.as_ref().and_then(|p| {
            if p.0.is_partial() {
                Some(p.0.clone())
            } else {
                None
            }
        }),
        partial_q: args.q.as_ref().and_then(|q| {
            if q.0.is_partial() {
                Some(q.0.clone())
            } else {
                None
            }
        }),
        keys: Vec::new(),
    };

    // Add additional keys from multiple N, E, and C parameters
    // This supports various multi-key attack scenarios:
    // - Multiple N values: different moduli (e.g., common factor, Hastad's broadcast)
    // - Single N, multiple E/C: same modulus, different exponents (e.g., common modulus)
    // - Multiple of each: fully specified keys
    let max_keys = args.n.len().max(args.e.len()).max(all_ciphers.len());

    for i in 1..max_keys {
        let n = args.n.get(i).map(|n| n.0.clone()).or_else(|| {
            // If there's only one N, reuse it for all keys (common modulus attack scenario)
            if args.n.len() == 1 {
                args.n.first().map(|n| n.0.clone())
            } else {
                None
            }
        });

        let e = args.e.get(i).map(|e| e.0.clone()).unwrap_or_else(|| {
            // Default to 65537 if not specified
            Integer::from(65537)
        });

        let c = all_ciphers.get(i).cloned();

        // Only add if at least one of n, e, or c is different from the main key
        if n.is_some() || c.is_some() || (i < args.e.len() && args.e.get(i).is_some()) {
            params.keys.push(KeyEntry { n, e, c });
        }
    }

    // Read public and private keys
    if !args.key.is_empty() {
        // First key becomes the main key
        if let Some(first_key) = args.key.first() {
            let bytes = std::fs::read(first_key)?;
            params += Parameters::from_private_key(&bytes, args.password.as_deref())
                .or_else(|| Parameters::from_public_key(&bytes))
                .ok_or("Invalid key")?;
        }

        // Additional keys go into the keys vector for multi-key attacks
        for key_path in args.key.iter().skip(1) {
            let bytes = std::fs::read(key_path)?;

            if let Some(key_params) = Parameters::from_private_key(&bytes, args.password.as_deref())
                .or_else(|| Parameters::from_public_key(&bytes))
            {
                params.keys.push(KeyEntry {
                    n: key_params.n,
                    e: key_params.e,
                    c: None,
                });
            } else {
                return Err(format!("Invalid key: {}", key_path).into());
            }
        }
    };

    if params.n.is_none() && params.keys.iter().all(|key| key.n.is_none()) {
        return Err("No input provided. Use --raw/--input, pipe raw text, provide key parameters, or create data.txt in the current directory.".into());
    }

    if args.showinputs {
        if json {
            print_json(&serde_json::json!({
                "version": current_version,
                "success": true,
                "parameters": params.to_string(),
            }));
        } else {
            println!("{params}");
        }
        return Ok(0);
    }

    // Check if discrete logarithm can be computed
    if args.dlog && params.c.is_none() {
        return Err("Discrete logarithm requires a cipher".into());
    }

    // Print public key
    if args.public {
        if let Some(n) = &params.n {
            let rsa = openssl::rsa::Rsa::from_public_components(
                openssl::bn::BigNum::from_slice(&n.to_digits(Order::Msf)).unwrap(),
                openssl::bn::BigNum::from_slice(&params.e.to_digits(Order::Msf)).unwrap(),
            )
            .or(Err("Invalid public key parameters"))?;
            let pem = rsa
                .public_key_to_pem()
                .map(|pem| String::from_utf8(pem).unwrap())
                .unwrap();
            if json {
                print_json(&serde_json::json!({
                    "version": current_version,
                    "success": true,
                    "public_key": pem,
                }));
            } else {
                print!("{pem}");
            }
            return Ok(0);
        } else {
            return Err("No public key found".into());
        }
    }

    // Build attack list
    let attacks = args
        .attack
        // Collect attacks
        .map(|attacks| {
            attacks
                .into_iter()
                .map(|attack| attack.0)
                .collect::<Vec<_>>()
        })
        .unwrap_or(ATTACKS.to_vec())
        // Exclude attacks
        .into_iter()
        .filter(|attack| {
            args.exclude
                .as_ref()
                .map(|exclude| !exclude.iter().any(|a| a.0.name() == attack.name()))
                .unwrap_or(true)
        })
        // Sort attacks by kind and speed
        .sorted_by_key(|a| (a.kind(), a.speed()))
        .collect::<Vec<_>>();

    // Run attacks
    let start = std::time::Instant::now();
    let res = rsacracker::run_specific_attacks_with_threads(&params, &attacks, args.threads);
    let elapsed = start.elapsed();

    let solution = match res {
        Ok(solution) => solution,
        Err(partial_factors) => {
            // Print partial factors only in human-readable mode.
            if !json {
                if let Some(partial_factors) = partial_factors {
                    println!("Partial factors of n:");
                    for (i, p) in partial_factors.as_vec().into_iter().enumerate() {
                        print!("p{} = {}", i + 1, p);
                        if p.is_probably_prime(100) != IsPrime::Yes {
                            print!(" (composite)");
                        }
                        println!();
                    }
                }
            }
            let error = format!(
                "No attack succeeded in {:.2}s. Consider:\n  \
                 - Adding more known parameters if available (--phi, --dp, --dq, etc.)\n  \
                 - The modulus might be cryptographically secure",
                elapsed.as_secs_f64()
            );
            if json {
                let mut report = error_report(&error);
                report["elapsed_seconds"] = serde_json::json!(elapsed.as_secs_f64());
                print_json(&report);
                return Ok(1);
            } else {
                return Err(error.into());
            }
        }
    };
    if json {
        let message = solution.m.as_ref().map(|value| {
            let bytes = integer_to_bytes(value);
            serde_json::json!({
                "integer": value.to_string(),
                "hex": format!("0x{value:02x}"),
                "string": integer_to_string(value),
                "bytes": bytes,
            })
        });
        let messages: Vec<_> = solution
            .ms
            .iter()
            .map(|value| {
                serde_json::json!({
                    "integer": value.to_string(),
                    "hex": format!("0x{value:02x}"),
                    "string": integer_to_string(value),
                    "bytes": integer_to_bytes(value),
                })
            })
            .collect();
        if let (Some(outfile), Some(value)) = (&args.outfile, &solution.m) {
            std::fs::write(outfile, integer_to_bytes(value))?;
        }
        for (value, i) in solution.ms.iter().zip(1..) {
            if let Some(outfile) = args
                .outfile
                .as_ref()
                .map(|path| suffix_path(path, &format!("_{i}")))
            {
                std::fs::write(outfile, integer_to_bytes(value))?;
            }
        }
        let mut report = serde_json::json!({
            "version": current_version,
            "success": true,
            "attack": solution.attack,
            "elapsed_seconds": elapsed.as_secs_f64(),
        });
        if let Some(message) = message {
            report["message"] = message;
        }
        if !messages.is_empty() {
            report["messages"] = serde_json::json!(messages);
        }
        if let Some(pk) = &solution.pk {
            report["private_key"] = serde_json::json!({
                "n": pk.n.to_string(),
                "e": pk.e.to_string(),
                "d": pk.d.to_string(),
                "factors": pk.factors.as_vec().iter().map(ToString::to_string).collect::<Vec<_>>(),
            });
        }
        print_json(&report);
        return Ok(0);
    }

    println!(
        "Success: {} attack completed in {:.2}s",
        solution.attack,
        elapsed.as_secs_f64()
    );

    // Show factors if explicitly requested, or by default when no ciphertext present in all input sources, and no other display mode
    let has_any_ciphertext = params.c.is_some() || params.keys.iter().any(|k| k.c.is_some());
    if args.factors || (!has_any_ciphertext && !args.private && !args.dump && !args.dumpext) {
        if let Some(private_key) = &solution.pk {
            println!("Factors of n:");
            if private_key.factors.len() == 2 {
                display_value("p", &private_key.p(), args.bits);
                display_value("q", &private_key.q(), args.bits);
            } else {
                for (i, p) in private_key.factors.as_vec().into_iter().enumerate() {
                    display_value(&format!("p{}", i + 1), p, args.bits);
                }
            }
        } else {
            return Err("No private key found".into());
        }
        return Ok(0);
    }

    // Print private key
    if args.private || args.dump || args.dumpext {
        if let Some(private_key) = &solution.pk {
            if args.private {
                print!("{}", private_key.to_pem(&args.addpassword).unwrap());
            }
            if args.dump || args.dumpext {
                println!("Private key:");
                display_value("n", &private_key.n, args.bits);
                display_value("e", &private_key.e, args.bits);

                // Print factors
                if private_key.factors.len() == 2 {
                    display_value("p", &private_key.p(), args.bits);
                    display_value("q", &private_key.q(), args.bits);
                } else {
                    for (i, p) in private_key.factors.as_vec().into_iter().enumerate() {
                        display_value(&format!("p{}", i + 1), p, args.bits);
                    }
                }
                display_value("d", &private_key.d, args.bits);
            }
            if args.dumpext {
                println!("Extended private key:");
                display_value("phi", &private_key.phi(), args.bits);
                display_value("dP", &private_key.dp(), args.bits);
                display_value("dQ", &private_key.dq(), args.bits);
                display_value("pInv", &private_key.pinv(), args.bits);
                display_value("qInv", &private_key.qinv(), args.bits);
            }
        } else {
            return Err("No private key found".into());
        }
        return Ok(0);
    }

    // Print unciphered data
    if let Some(uncipher) = solution.m {
        display_or_output(&uncipher, &args.outfile)?;

        // Print discrete logarithm
        if args.dlog {
            if let Some(pk) = &solution.pk {
                println!("Compute discrete logarithm...");
                if let Ok(dlog) = discrete_log_with_factors(
                    &pk.n,
                    &params.c.unwrap(),
                    &pk.e,
                    &pk.factors.to_hash_map(),
                ) {
                    display_or_output(&dlog, &args.outfile.map(|f| suffix_path(&f, "_dlog")))?;
                } else {
                    return Err("Discrete logarithm failed".into());
                }
            } else {
                return Err("Discrete requires a private key".into());
            }
        }
    }
    // Print multiple unciphered data
    else if !solution.ms.is_empty() {
        println!("Multiple unciphered data found:");
        for (uncipher, i) in solution.ms.iter().zip(1..) {
            println!();
            display_or_output(
                uncipher,
                &args
                    .outfile
                    .clone()
                    .map(|f| suffix_path(&f, &format!("_{i}"))),
            )?;
        }
    }

    Ok(0)
}

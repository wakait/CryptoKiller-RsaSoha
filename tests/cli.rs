fn run_bin(args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rsacracker"));
    cmd.args(args)
        .env("RSACRACKER_DISABLE_UPDATE", "1")
        .output()
        .expect("failed to run rsacracker binary")
}

#[test]
fn help_is_chinese_for_short_and_long_flags() {
    for flag in ["-h", "--help"] {
        let output = run_bin(&[flag]);
        assert!(output.status.success(), "{flag} should exit successfully");

        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in [
            "用法:",
            "选项:",
            "从 raw 文件读取参数",
            "显示帮助信息",
            "显示版本信息",
            "--json",
            "--attack",
            "--partial-d",
            "--partial-d-bits",
            "--d-known-msb",
            "--d-unknown-bits",
            "--m-known",
            "--m-unknown-bits",
            "--related-c",
            "--related-a1",
            "--related-b1",
            "--related-a2",
            "--related-b2",
        ] {
            assert!(
                stdout.contains(expected),
                "{flag} help is missing {expected:?}:\n{stdout}"
            );
        }
        for english in [
            "Usage:",
            "Options:",
            "Print help",
            "Print version",
            "[default:",
        ] {
            assert!(
                !stdout.contains(english),
                "{flag} help still contains {english:?}:\n{stdout}"
            );
        }
    }
}

#[test]
fn all_advanced_attacks_are_listed_with_parameters() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let details = report["attack_details"].as_array().unwrap();
    for name in [
        "coppersmith_factor",
        "coppersmith_message",
        "partial_d_msb",
        "boneh_durfee",
        "franklin_reiter",
    ] {
        let attack = details
            .iter()
            .find(|attack| attack["name"] == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert!(
            attack["required_parameters"]
                .as_array()
                .is_some_and(|parameters| !parameters.is_empty()),
            "{name} must expose required parameters"
        );
    }
}

#[test]
fn advanced_help_is_chinese_and_complete() {
    let output = run_bin(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--search-budget",
        "--m-known",
        "--m-unknown-bits",
        "--d-known-msb",
        "--d-unknown-bits",
        "--related-c",
        "--related-a1",
        "--related-b1",
        "--related-a2",
        "--related-b2",
    ] {
        assert!(stdout.contains(flag), "missing {flag}");
    }
}

#[test]
fn help_and_list_expose_search_budget_contract() {
    let help = run_bin(&["-h"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--search-budget"));
    let list = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| {
            a["name"] == "partial_prime"
                && a["required_parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p == "partial_p|partial_q|p|q")
        }));
}

// picoCTF 2019 b00tl3gRSA2 parameters (Wiener attack)
const N: &str = "93596195645610503452177719837666902345047461004926714393186384188598288812343005592124086521572864457489909063543756427769917131437307447863586528928496194559057760628385975297585140789577911616474493538014622500120560643072265673362843715324209056486085041020831625385434745566998218712055519575753745124619";
const E: &str = "1595235523996321655798747471789583440185208568327862733680046250799766370193739982702940394656406146131440688831932739213253542820322450207724280220533900355744553772981019201731036379810734890063829650829319133004906034534031330743611288482822751674556919861911431941749713177767003275664528498846275096193";
const C: &str = "78394077185972242522366494812194999029111007804513916081388100744678077142246684573709463174914072230588766938274935729449697899122556506361108922139286130431073819269477944903949010409297739704373353086560177410340042335176831160010922826152074048460889509110907225759217407138633733239524781798190577093673";
const FLAG: &str = "picoCTF{bad_1d3a5_2152720}";

// Cipher present via --raw file -> decrypt, no factor output
#[test]
fn raw_file_with_cipher_decrypts() {
    let output = run_bin(&[
        "--raw",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/raw/picoctf_2019_b00tl3grsa2.txt"
        ),
        "--attack=wiener",
    ]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FLAG),
        "expected decrypted flag in stdout, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Factors of n:"),
        "must not print factors when cipher is present in raw file, got:\n{stdout}"
    );
}

// No cipher in --raw file -> show factors by default, no decryption output
#[test]
fn raw_file_without_cipher_shows_factors() {
    let output = run_bin(&[
        "--raw",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/raw/no_cipher_wiener.txt"
        ),
        "--attack=wiener",
    ]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Factors of n:"),
        "expected factor output when no cipher is present in raw file, got:\n{stdout}"
    );
    assert!(
        stdout.contains("p =") && stdout.contains("q ="),
        "expected p and q in factor output, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Unciphered data:"),
        "must not print decryption output when no cipher is present, got:\n{stdout}"
    );
}

// Cipher present via -c flag -> decrypt, no factor output
#[test]
fn cli_flags_with_cipher_decrypts() {
    let output = run_bin(&["-n", N, "-e", E, "-c", C, "--attack=wiener"]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FLAG),
        "expected decrypted flag in stdout, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Factors of n:"),
        "must not print factors when -c flag is provided, got:\n{stdout}"
    );
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rsacracker-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_bin_in_dir(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rsacracker"))
        .args(args)
        .current_dir(dir)
        .env("RSACRACKER_DISABLE_UPDATE", "1")
        .output()
        .expect("failed to run rsacracker binary")
}

const SIMPLE_RAW: &str = "p = 170141183460469231731687303715884105727\nq = 162259276829213363391578010288127\ne = 65537\nc = 21276652172097553670859187083144524567044111056787806718560215689585764\n";

const PARTIAL_PRIME_RAW: &str = "n = 3233\ne = 17\np = 0x3?\n";

#[test]
fn cli_coppersmith_factor_recovers_msb_with_zero_enumeration_budget() {
    use std::str::FromStr;

    let p = rug::Integer::from_str(
        "112219243609243706223486619551298085362360091408633161457003404046681540344297",
    )
    .unwrap();
    let q = rug::Integer::from_str(
        "64052533192509995760322742160163582601357132095571262796409705234000154367147",
    )
    .unwrap();
    let n = rug::Integer::from(&p * &q).to_string();
    let known = p.clone() >> 40;
    let partial_p = format!("0x{known:x}??????????");
    let output = run_bin(&[
        "-n",
        &n,
        "-p",
        &partial_p,
        "--attack=coppersmith_factor",
        "--search-budget",
        "0",
        "--threads=1",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "coppersmith_factor");
    assert_eq!(report["private_key"]["n"], n);
    let factors = report["private_key"]["factors"].as_array().unwrap();
    assert!(factors.contains(&serde_json::json!(p.to_string())));
    assert!(factors.contains(&serde_json::json!(q.to_string())));
}

#[test]
fn cli_coppersmith_message_decrypts_and_reports_attack() {
    let output = run_bin(&[
        "-n",
        "1000036000099",
        "-e",
        "5",
        "-c",
        "819449521559",
        "--m-known",
        "964",
        "--m-unknown-bits",
        "7",
        "--attack=coppersmith_message",
        "--threads=1",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "coppersmith_message");
    assert_eq!(report["message"]["integer"], "123456");
    assert!(report["private_key"].is_null());
}

#[test]
fn cli_coppersmith_message_fields_are_merged_after_raw() {
    let dir = TempDir::new("message-msb-merge");
    let input = dir.0.join("data.txt");
    std::fs::write(
        &input,
        "n = 1000036000099\ne = 5\nc = 819449521559\nm_known = 0\nm_unknown_bits = 1\n",
    )
    .unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--m-known",
            "964",
            "--m-unknown-bits",
            "7",
            "--attack=coppersmith_message",
            "--threads=1",
            "--json",
        ],
    );

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["message"]["integer"], "123456");
}

#[test]
fn cli_coppersmith_message_rejects_unpaired_fields() {
    for (args, expected) in [
        (vec!["-n", "1000036000099", "--m-known", "964"], "m_known"),
        (
            vec!["-n", "1000036000099", "--m-unknown-bits", "7"],
            "m_unknown_bits",
        ),
    ] {
        let mut args = args;
        args.push("--json");
        let output = run_bin(&args);

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], false);
        assert!(report["error"].as_str().unwrap().contains(expected));
    }
}

#[test]
fn cli_coppersmith_message_rejects_excessive_unknown_bits() {
    let output = run_bin(&[
        "-n",
        "3233",
        "--m-known",
        "0",
        "--m-unknown-bits",
        "13",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert!(report["error"].as_str().unwrap().contains("m_unknown_bits"));
}

#[test]
fn json_list_contains_coppersmith_message() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "coppersmith_message")
        .unwrap();
    assert_eq!(
        attack["required_parameters"],
        serde_json::json!(["n", "e", "c", "m_known+m_unknown_bits"])
    );
}

#[test]
fn json_list_contains_franklin_reiter() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "franklin_reiter")
        .unwrap();
    assert_eq!(
        attack["required_parameters"],
        serde_json::json!([
            "n",
            "e",
            "c",
            "related_c+related_a1+related_b1+related_a2+related_b2"
        ])
    );
}

#[test]
fn cli_franklin_reiter_recovers_related_message() {
    let output = run_bin(&[
        "-n",
        "3233",
        "-e",
        "3",
        "-c",
        "1680",
        "--related-c",
        "1411",
        "--related-a1",
        "2",
        "--related-b1",
        "3",
        "--related-a2",
        "3",
        "--related-b2",
        "5",
        "--attack=franklin_reiter",
        "--threads=1",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "franklin_reiter");
    assert_eq!(report["message"]["integer"], "7");
    assert!(report["private_key"].is_null());
}

#[test]
fn cli_franklin_reiter_rejects_unpaired_fields() {
    for missing in [
        "--related-c",
        "--related-a1",
        "--related-b1",
        "--related-a2",
        "--related-b2",
    ] {
        let args = [
            "-n",
            "3233",
            "-e",
            "3",
            "-c",
            "1680",
            "--related-c",
            "1411",
            "--related-a1",
            "2",
            "--related-b1",
            "3",
            "--related-a2",
            "3",
            "--related-b2",
            "5",
            "--json",
        ];
        let mut filtered = Vec::new();
        let mut skip_value = false;
        for arg in args {
            if skip_value {
                skip_value = false;
                continue;
            }
            if arg == missing {
                skip_value = true;
            } else {
                filtered.push(arg);
            }
        }
        let output = run_bin(&filtered);
        assert_eq!(output.status.code(), Some(2), "missing {missing}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], false);
        assert!(report["error"]
            .as_str()
            .unwrap()
            .contains("provided together"));
    }
}

#[test]
fn cli_boneh_durfee_recovers_large_lattice_fixture_with_zero_budget() {
    let output = run_bin(&[
        "-n",
        "4228333",
        "-e",
        "2816147",
        "--attack=boneh_durfee",
        "--search-budget",
        "0",
        "--threads=1",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "boneh_durfee should solve the Y>2047 lattice fixture. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "boneh_durfee");
    assert_eq!(report["private_key"]["n"], "4228333");
    assert_eq!(report["private_key"]["d"], "3");
    assert_eq!(
        report["private_key"]["factors"],
        serde_json::json!(["2003", "2111"])
    );
}

#[test]
fn json_list_contains_boneh_durfee() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "boneh_durfee")
        .unwrap();
    assert_eq!(attack["required_parameters"], serde_json::json!(["n", "e"]));
}

#[test]
fn cli_partial_d_msb_recovers_fixed_key() {
    let output = run_bin(&[
        "-n",
        "3233",
        "-e",
        "17",
        "-c",
        "2557",
        "--d-known-msb",
        "172",
        "--d-unknown-bits",
        "4",
        "--attack=partial_d_msb",
        "--threads=1",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "partial d MSB should solve the key. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "partial_d_msb");
    assert_eq!(report["message"]["integer"], "42");
    assert_eq!(report["private_key"]["d"], "2753");
    assert_eq!(
        report["private_key"]["factors"],
        serde_json::json!(["53", "61"])
    );
}

#[test]
fn cli_partial_d_msb_fields_override_raw() {
    let dir = TempDir::new("partial-d-msb-override");
    let input = dir.0.join("data.txt");
    std::fs::write(
        &input,
        "n = 3233\ne = 17\nc = 2557\nd_known_msb = 170\nd_unknown_bits = 4\n",
    )
    .unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--d-known-msb",
            "172",
            "--d-unknown-bits",
            "4",
            "--attack=partial_d_msb",
            "--threads=1",
            "--json",
        ],
    );

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["private_key"]["d"], "2753");
}

#[test]
fn cli_partial_d_msb_zero_unknown_bits_overrides_raw() {
    let dir = TempDir::new("partial-d-msb-zero-override");
    let input = dir.0.join("data.txt");
    std::fs::write(
        &input,
        "n = 3233\ne = 17\nc = 2557\nd_known_msb = 2753\nd_unknown_bits = 4\n",
    )
    .unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--d-known-msb",
            "2753",
            "--d-unknown-bits",
            "0",
            "--attack=partial_d_msb",
            "--threads=1",
            "--json",
        ],
    );

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["private_key"]["d"], "2753");
}

#[test]
fn cli_partial_d_msb_rejects_invalid_fields() {
    for (args, expected) in [
        (vec!["-n", "3233", "--d-known-msb", "172"], "d_known_msb"),
        (
            vec!["-n", "3233", "--d-unknown-bits", "4"],
            "d_unknown_bits",
        ),
        (
            vec![
                "-n",
                "3233",
                "--d-known-msb",
                "172",
                "--d-unknown-bits",
                "13",
            ],
            "d_unknown_bits",
        ),
    ] {
        let mut args = args;
        args.push("--json");
        let output = run_bin(&args);

        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], false);
        assert!(report["error"].as_str().unwrap().contains(expected));
    }
}

#[test]
fn partial_d_msb_cli_fields_count_as_direct_input() {
    let dir = TempDir::new("partial-d-msb-direct-input");
    std::fs::write(
        dir.0.join("data.txt"),
        "n = 3233\ne = 17\nd_known_msb = 172\nd_unknown_bits = 4\n",
    )
    .unwrap();

    for args in [
        vec!["--d-known-msb", "172", "--json"],
        vec!["--d-unknown-bits", "4", "--json"],
    ] {
        let output = run_bin_in_dir(&dir.0, &args);
        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["error"]
            .as_str()
            .unwrap()
            .contains("must be provided together"));
    }
}

#[test]
fn json_list_contains_partial_d_msb() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "partial_d_msb")
        .unwrap();
    assert_eq!(
        attack["required_parameters"],
        serde_json::json!(["n", "e", "d_known_msb+d_unknown_bits"])
    );
}

#[test]
fn showinputs_exposes_partial_d_msb_fields() {
    let output = run_bin(&[
        "-n",
        "3233",
        "--d-known-msb",
        "172",
        "--d-unknown-bits",
        "0",
        "--showinputs",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("d_known_msb = 172"));
    assert!(stdout.contains("d_unknown_bits = 0"));
}

#[test]
fn cli_zero_search_budget_disables_partial_prime_enumeration() {
    let dir = TempDir::new("cli-zero-budget");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, PARTIAL_PRIME_RAW).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--search-budget",
            "0",
            "--attack=partial_prime",
            "--threads=1",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
}

#[test]
fn raw_zero_search_budget_is_not_overwritten_by_cli_default() {
    let dir = TempDir::new("raw-zero-budget");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, format!("{PARTIAL_PRIME_RAW}search_budget = 0\n")).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--attack=partial_prime",
            "--threads=1",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
}

#[test]
fn explicit_cli_search_budget_overrides_raw_custom_budget() {
    let dir = TempDir::new("cli-budget-override");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, format!("{PARTIAL_PRIME_RAW}search_budget = 0\n")).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--search-budget",
            "16",
            "--attack=partial_prime",
            "--threads=1",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "partial_prime");
}

#[test]
fn explicit_zero_cli_search_budget_overrides_raw_custom_budget() {
    let dir = TempDir::new("cli-zero-budget-override");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, format!("{PARTIAL_PRIME_RAW}search_budget = 16\n")).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--search-budget",
            "0",
            "--attack=partial_prime",
            "--threads=1",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
}

#[test]
fn showinputs_exposes_cli_search_budget() {
    let output = run_bin(&["-n", "3233", "--search-budget", "0", "--showinputs"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("search_budget = 0"));
}

#[test]
fn raw_known_primes_without_modulus_decrypts() {
    let dir = TempDir::new("derive-n");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, SIMPLE_RAW).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &["--raw", input.to_str().unwrap(), "--attack=leaked_pq"],
    );

    assert!(output.status.success(), "known primes should solve the key");
    assert!(String::from_utf8_lossy(&output.stdout).contains("rsacracker{windows_cli}"));
}

#[test]
fn cli_known_primes_without_modulus_decrypts() {
    let output = run_bin(&[
        "-p",
        "170141183460469231731687303715884105727",
        "-q",
        "162259276829213363391578010288127",
        "-e",
        "65537",
        "-c",
        "21276652172097553670859187083144524567044111056787806718560215689585764",
        "--attack=leaked_pq",
    ]);

    assert!(
        output.status.success(),
        "known primes should derive n. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("rsacracker{windows_cli}"));
}

#[test]
fn cli_partial_d_decrypts() {
    let output = run_bin(&[
        "-n",
        "3233",
        "-e",
        "17",
        "-c",
        "2557",
        "--partial-d",
        "193",
        "--partial-d-bits",
        "8",
        "--attack=partial_d",
        "--threads=1",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "partial d should solve the key. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["message"]["integer"], "42");
}

#[test]
fn json_output_is_machine_readable() {
    let dir = TempDir::new("json-success");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, SIMPLE_RAW).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--input",
            input.to_str().unwrap(),
            "--attack=leaked_pq",
            "--threads=1",
            "--json",
        ],
    );

    assert!(output.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only JSON");
    assert_eq!(report["success"], true);
    assert_eq!(report["attack"], "leaked_pq");
    assert_eq!(report["message"]["string"], "rsacracker{windows_cli}");
    assert!(report["elapsed_seconds"].is_f64());
}

#[test]
fn no_arguments_reads_data_txt_from_current_directory() {
    let dir = TempDir::new("default-input");
    std::fs::write(dir.0.join("data.txt"), SIMPLE_RAW).unwrap();
    let output = run_bin_in_dir(&dir.0, &["--attack=leaked_pq", "--threads=1"]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("rsacracker{windows_cli}"));
}

#[test]
fn invalid_raw_field_returns_input_error_as_json() {
    let dir = TempDir::new("invalid-raw");
    let input = dir.0.join("invalid.txt");
    std::fs::write(&input, "n = not-a-number\n").unwrap();
    let output = run_bin_in_dir(&dir.0, &["--raw", input.to_str().unwrap(), "--json"]);

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert!(report["error"].as_str().unwrap().contains("n"));
}

#[test]
fn no_successful_attack_returns_distinct_exit_code() {
    let output = run_bin(&["-n", "17", "--attack=small_prime", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("No attack succeeded"));
}

#[test]
fn zero_budget_human_mode_returns_attack_failure_exit_code() {
    let dir = TempDir::new("human-zero-budget");
    let input = dir.0.join("data.txt");
    std::fs::write(&input, PARTIAL_PRIME_RAW).unwrap();
    let output = run_bin_in_dir(
        &dir.0,
        &[
            "--raw",
            input.to_str().unwrap(),
            "--search-budget",
            "0",
            "--attack=partial_prime",
            "--threads=1",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No attack succeeded"));
}

#[test]
fn json_list_contains_coppersmith_factor() {
    let output = run_bin(&["--list", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let attack = report["attack_details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "coppersmith_factor")
        .unwrap();
    assert_eq!(
        attack["required_parameters"],
        serde_json::json!(["n", "e", "partial_p|partial_q"])
    );
}

#[test]
fn json_list_is_machine_readable() {
    let output = run_bin(&["--list", "--json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert!(report["attacks"].as_array().unwrap().len() > 1);
    let details = report["attack_details"].as_array().unwrap();
    let known_d = details
        .iter()
        .find(|attack| attack["name"] == "known_d")
        .unwrap();
    assert_eq!(
        known_d["required_parameters"],
        serde_json::json!(["n", "e", "d"])
    );
    let partial_d = details
        .iter()
        .find(|attack| attack["name"] == "partial_d")
        .unwrap();
    assert_eq!(
        partial_d["required_parameters"],
        serde_json::json!(["n", "e", "partial_d|d"])
    );
}

#[test]
fn human_list_shows_required_parameters() {
    let output = run_bin(&["--list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("所需参数"));
    assert!(stdout.contains("known_d"));
    assert!(stdout.contains("n, e, d"));
    assert!(stdout.contains("coppersmith_factor"));
    assert!(stdout.contains("n, e, partial_p|partial_q"));
}

#[test]
fn json_public_key_is_machine_readable() {
    let output = run_bin(&[
        "--key",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/keys/public_rsa.pem"),
        "--public",
        "--json",
    ]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert!(report["public_key"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PUBLIC KEY-----"));
}

// --factors flag forces factor output even when cipher is present, no decryption output
#[test]
fn cli_flags_with_cipher_and_factors_flag_shows_factors() {
    let output = run_bin(&["-n", N, "-e", E, "-c", C, "--attack=wiener", "--factors"]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Factors of n:"),
        "expected factor output when --factors is passed, got:\n{stdout}"
    );
    assert!(
        !stdout.contains(FLAG),
        "must not print decryption output when --factors is passed, got:\n{stdout}"
    );
}

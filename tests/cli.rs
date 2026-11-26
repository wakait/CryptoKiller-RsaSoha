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
fn json_list_is_machine_readable() {
    let output = run_bin(&["--list", "--json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert!(report["attacks"].as_array().unwrap().len() > 1);
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

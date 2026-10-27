use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn escaped_string_literals_match_all_execution_modes() {
    let s = Sandbox::new();
    let script = s.write(
        "escaped-strings.gak",
        r#"from std.text import length, byte_length
print "\u{1F600}"
print "\x41\0B"
print "\u{e9}" == "é"
print "\xE9" == "é"
print byte_length("\xE9")
print length("\u{1F600}")
print byte_length("\u{1F600}")
"#,
    );
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let expected = "😀\nA\0B\ntrue\ntrue\n2\n1\n4\n".as_bytes();
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected, "{engine}");
    }
    let built = Command::new(binary)
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed = Command::new(binary)
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_eq!(executed.stdout, expected);
    if gcc_available() {
        let compiled = s.compile(&script);
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, expected);
    }
}

#[test]
fn malformed_string_escapes_have_source_locations() {
    let s = Sandbox::new();
    for (name, literal, message) in [
        ("short-hex", r#""\x4""#, "expected two hex digits after \\x"),
        (
            "invalid-hex",
            r#""\x4G""#,
            "expected two hex digits after \\x",
        ),
        ("empty-unicode", r#""\u{}""#, "expected 1-6 hex digits"),
        ("surrogate", r#""\u{d800}""#, "invalid Unicode scalar value"),
        (
            "too-large",
            r#""\u{110000}""#,
            "invalid Unicode scalar value",
        ),
        (
            "too-long",
            r#""\u{0000000}""#,
            "Unicode escape exceeds six hex digits",
        ),
        ("missing-brace", r#""\u1234""#, "expected '{' after \\u"),
    ] {
        let script = s.write(&format!("{name}.gak"), &format!("print {literal}\n"));
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(script)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("1:8:"), "{name}: {error}");
        assert!(error.contains(message), "{name}: {error}");
    }
}

#[test]
fn native_format_print_matches_ast_vm_and_bundle() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut elf = [0_u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&1_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    fs::write(s.0.join("header.elf"), elf).unwrap();
    let script = s.write(
        "format-print.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe\nlet report: Format = probe(analyze(\"header.elf\", 64))\nprint report\n",
    );
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let mut expected = None;
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(bytes) = &expected {
            assert_eq!(&output.stdout, bytes, "{engine}");
        } else {
            expected = Some(output.stdout);
        }
    }
    let built = Command::new(binary)
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let bundle = Command::new(binary)
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        bundle.status.success(),
        "{}",
        String::from_utf8_lossy(&bundle.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let expected = expected.unwrap();
    assert_eq!(bundle.stdout, expected);
    assert_eq!(native.stdout, expected);
    assert!(String::from_utf8_lossy(&expected).ends_with(
        "ELF64 little-endian machine=0x003e entry_va=0x400000 sections=0 header=[0..64)\n"
    ));

    let mut pe = vec![0_u8; 0x110];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&1_u16.to_le_bytes());
    pe[0x54..0x56].copy_from_slice(&112_u16.to_le_bytes());
    pe[0x58..0x5a].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[0x68..0x6c].copy_from_slice(&0x1234_u32.to_le_bytes());
    pe[0xc8..0xcc].copy_from_slice(b".x\"\\");
    pe[0xd0..0xd4].copy_from_slice(&0x20_u32.to_le_bytes());
    pe[0xd4..0xd8].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[0xd8..0xdc].copy_from_slice(&0x10_u32.to_le_bytes());
    pe[0xdc..0xe0].copy_from_slice(&0x100_u32.to_le_bytes());
    pe[0xec..0xf0].copy_from_slice(&0x60000020_u32.to_le_bytes());
    fs::write(s.0.join("header.pe"), pe).unwrap();
    let pe_script = s.write(
        "pe-format-print.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, section\nlet report = probe(analyze(\"header.pe\", 272))\nprint report\nprint section(report, 0)\n",
    );
    let vm = Command::new(binary)
        .arg("run")
        .arg(&pe_script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let pe_compiled = s.compile(&pe_script);
    assert!(
        pe_compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&pe_compiled.stderr)
    );
    let pe_executable = PathBuf::from(String::from_utf8(pe_compiled.stdout).unwrap().trim());
    let pe_native = Command::new(pe_executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        pe_native.status.success(),
        "{}",
        String::from_utf8_lossy(&pe_native.stderr)
    );
    assert_eq!(pe_native.stdout, vm.stdout);
    let printed = String::from_utf8_lossy(&vm.stdout);
    assert!(printed.contains(
        "PE32+ little-endian machine=0x8664 entry_rva=0x1234 sections=1 header=[0..240)\nsection(\".x\\\"\\\\\", file=[256..272), va=0x1000, virtual_size=32, flags=0x60000020, writable=false, executable=true, source_sha256:"
    ), "{printed}");
    assert!(printed.ends_with(")\n"));

    let mut unnamed_elf = [0_u8; 128];
    unnamed_elf[..64].copy_from_slice(&elf);
    unnamed_elf[40..48].copy_from_slice(&64_u64.to_le_bytes());
    unnamed_elf[58..60].copy_from_slice(&64_u16.to_le_bytes());
    unnamed_elf[60..62].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(s.0.join("unnamed.elf"), unnamed_elf).unwrap();
    let unnamed_script = s.write(
        "unnamed-section.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, section\nprint section(probe(analyze(\"unnamed.elf\", 128)), 0)\n",
    );
    let vm = Command::new(binary)
        .arg("run")
        .arg(&unnamed_script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&unnamed_script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&vm.stdout).starts_with("section(\"<name unavailable>\""));
}

#[test]
fn unicode_text_module_matches_ast_vm_bundle_and_native() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "text_helpers.gaks",
        "import std.text as text\nfn middle(value: str) -> str = text.slice(value, 1, 2)\n",
    );
    let script = s.write(
        "text-main.gak",
        "import text_helpers as helper\nfrom std.text import length, byte_length, find, contains, starts_with, ends_with, slice\nfrom std.result import is_error, message\nfn invalid() -> Result<str> = slice(\"Aλ😀Z\", 4, 1)\nfn negative() -> Result<str> = slice(\"Aλ😀Z\", -1, 1)\nfn huge() -> Result<str> = slice(\"Aλ😀Z\", 9223372036854775807, 9223372036854775807)\nlet value = \"Aλ😀Z\"\nprint length(value)\nprint byte_length(value)\nprint find(value, \"😀\")\nprint find(value, \"missing\")\nprint contains(value, \"λ😀\")\nprint contains(value, \"Zλ\")\nprint starts_with(value, \"Aλ\")\nprint ends_with(value, \"😀Z\")\nprint helper.middle(value)\nprint slice(value, 4, 0) == \"\"\nprint is_error(invalid())\nprint is_error(negative())\nprint is_error(huge())\nprint message(invalid())\nprint find(\"aaaaab\", \"aaab\")\nprint find(\"A\0B\", \"\0B\")\nprint find(value, \"\")\n",
    );
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let mut outputs = Vec::new();
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        outputs.push(output.stdout);
    }
    let built = Command::new(binary)
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let bundle = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let executed = Command::new(binary)
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    for output in [&outputs[0], &outputs[1], &executed.stdout, &native.stdout] {
        assert!(output.starts_with(b"4\n8\n2\n-1\ntrue\nfalse\ntrue\ntrue\n"));
        assert!(String::from_utf8_lossy(output).contains("λ😀\ntrue\ntrue\ntrue\ntrue\n"));
        assert!(String::from_utf8_lossy(output).contains("text slice out of range"));
        assert!(output.ends_with(b"2\n1\n0\n"));
    }
    assert_eq!(outputs[1], outputs[0]);
    assert_eq!(executed.stdout, outputs[0]);
}

#[test]
fn text_module_rejects_incorrect_types_before_execution() {
    let s = Sandbox::new();
    let script = s.write(
        "text-type.gak",
        "from std.text import length\nprint length(7)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr)
        .contains("text.length argument 1: expected str, got i64"));
}

#[test]
fn string_concatenation_matches_ast_vm_and_native_across_modules() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "joiner.gaks",
        "fn join(left: str, right: str) -> str = left + right\n",
    );
    let script = s.write(
        "main.gak",
        "import joiner\nlet prefix: str = \"Galeikan\"\nprint joiner.join(prefix, \"Script\")\nprint \"λ\" + \"\0\" + \"X\"\nprint joiner.join(\"\", \"\") == \"\"\n",
    );
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let mut outputs = Vec::new();
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        outputs.push(output.stdout);
    }
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(outputs[0], b"GaleikanScript\n\xce\xbb\0X\ntrue\n");
    assert_eq!(outputs[1], outputs[0]);
    assert_eq!(native.stdout, outputs[0]);
}

#[test]
fn string_concatenation_limit_is_captured_in_all_engines() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "string-limit.gak",
        "from std.result import is_error, message\nfn grow() -> Result<str> {\n    var value: str = \"x\"\n    var steps = 0\n    while steps < 27 {\n        value = value + value\n        steps = steps + 1\n    }\n    return value\n}\nlet outcome = grow()\nprint is_error(outcome)\nprint message(outcome)\n",
    );
    let binary = env!("CARGO_BIN_EXE_galeikan");
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with("true\n"), "{stdout}");
        assert!(stdout.contains("string memory exceeds 64 MiB"), "{stdout}");
    }
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let stdout = String::from_utf8_lossy(&native.stdout);
    assert!(stdout.starts_with("true\n"), "{stdout}");
    assert!(stdout.contains("string memory exceeds 64 MiB"), "{stdout}");
}

fn python_command() -> &'static str {
    if cfg!(windows) {
        "python"
    } else {
        "python3"
    }
}

fn python_available() -> bool {
    Command::new(python_command())
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn native_udp_datagram_matches_vm_and_enforces_grant_and_limit() {
    if !gcc_available() {
        return;
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let endpoint = socket.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "udp.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import datagram\nfrom std.binary import size, extract\nfrom std.bytes import to_hex\nfrom std.cli import int as argument_int\nlet reply: Source = datagram(\"127.0.0.1\", {}, \"PING\", argument_int(0), 2000)\nprint to_hex(extract(reply, 0, size(reply)))\nprint reply\n",
            socket.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable)
        .args(["--", "5"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("network access not allowed"));

    let server = thread::spawn(move || {
        let mut request = [0; 16];
        for _ in 0..4 {
            let (size, peer) = socket.recv_from(&mut request).unwrap();
            assert_eq!(&request[..size], b"PING");
            socket.send_to(&[0, 0xff, b'A', b'B', b'C'], peer).unwrap();
        }
    });
    let run_vm = |limit: &str| {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint, "--", limit])
            .output()
            .unwrap()
    };
    let run_native = |limit: &str| {
        Command::new(&executable)
            .args(["--allow-connect", &endpoint, "--", limit])
            .output()
            .unwrap()
    };
    let vm = run_vm("5");
    let native = run_native("5");
    let vm_limited = run_vm("4");
    let native_limited = run_native("4");
    server.join().unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(b"00ff414243\n"));
    assert!(String::from_utf8_lossy(&native.stdout).contains(&format!("udp://{endpoint}")));
    assert!(!vm_limited.status.success());
    assert!(!native_limited.status.success());
    assert!(String::from_utf8_lossy(&vm_limited.stderr)
        .contains("LimitExceeded: UDP datagram exceeds 4 bytes"));
    assert!(String::from_utf8_lossy(&native_limited.stderr)
        .contains("LimitExceeded: UDP datagram exceeds 4 bytes"));
}

#[test]
fn native_udp_datagram_times_out_without_response() {
    if !gcc_available() {
        return;
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let endpoint = socket.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "udp-timeout.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import datagram\nfrom std.binary import size\nprint size(datagram(\"127.0.0.1\", {}, \"PING\", 4, 100))\n",
            socket.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let server = thread::spawn(move || {
        let mut request = [0; 16];
        let mut received = 0;
        for _ in 0..2 {
            let Ok((size, _)) = socket.recv_from(&mut request) else {
                break;
            };
            assert_eq!(&request[..size], b"PING");
            received += 1;
        }
        received
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint]),
        Duration::from_secs(8),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint]),
        Duration::from_secs(8),
    );
    assert_eq!(
        server.join().unwrap(),
        2,
        "VM stderr: {}; native stderr: {}",
        String::from_utf8_lossy(&vm.stderr),
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("UDP exchange timed out"));
    assert!(String::from_utf8_lossy(&native.stderr).contains("UDP exchange timed out"));
}

#[test]
fn native_udp_datagram_accepts_ipv6_when_loopback_is_available() {
    if !gcc_available() {
        return;
    }
    let Ok(socket) = UdpSocket::bind("[::1]:0") else {
        return;
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let endpoint = socket.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "udp-ipv6.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import datagram\nfrom std.binary import size\nlet reply: Source = datagram(\"::1\", {}, \"PING\", 3, 2000)\nprint size(reply)\nprint reply\n",
            socket.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let server = thread::spawn(move || {
        let mut request = [0; 16];
        for _ in 0..2 {
            let (size, peer) = socket.recv_from(&mut request).unwrap();
            assert_eq!(&request[..size], b"PING");
            socket.send_to(b"ACK", peer).unwrap();
        }
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    server.join().unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains(&format!("udp://{endpoint}")));
}

#[test]
fn native_udp_datagram_rejects_oversized_request_before_sending() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "udp-request-limit.gak",
        "requires { net.connect }\nfrom std.net import datagram\nfrom std.bytes import from_hex, repeat\nprint datagram(\"127.0.0.1\", 9, repeat(from_hex(\"01\"), 65508), 1, 100)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-connect", "127.0.0.1:9"])
        .output()
        .unwrap();
    let native = Command::new(&executable)
        .args(["--allow-connect", "127.0.0.1:9"])
        .output()
        .unwrap();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("request exceeds 65507 bytes"));
    assert!(String::from_utf8_lossy(&native.stderr).contains("request exceeds 65507 bytes"));
}

#[test]
fn native_tcp_exchange_matches_vm_and_requires_target_grant() {
    if !gcc_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "tcp.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import exchange\nfrom std.binary import size, deep, value\nfrom std.cli import int as argument_int\nlet reply: Source = exchange(\"127.0.0.1\", {}, \"PING\", argument_int(0), 2000)\nprint size(reply)\nprint value(deep(reply, 0, \"u32be\"))\nprint reply\n",
            listener.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable)
        .args(["--", "4"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("network access not allowed"));

    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for _ in 0..4 {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "test TCP listener timed out");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test TCP listener failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING");
            stream.write_all(b"ABCD").unwrap();
        }
    });
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-connect", &address, "--", "4"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let native = Command::new(&executable)
        .args(["--allow-connect", &address, "--", "4"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    let vm_limited = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-connect", &address, "--", "2"])
        .output()
        .unwrap();
    let native_limited = Command::new(&executable)
        .args(["--allow-connect", &address, "--", "2"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!vm_limited.status.success());
    assert!(!native_limited.status.success());
    assert!(String::from_utf8_lossy(&native_limited.stderr)
        .contains("LimitExceeded: TCP response exceeds 2 bytes"));
    assert_eq!(native_limited.stderr, vm_limited.stderr);
}

#[test]
fn native_tcp_exchange_times_out_when_peer_stays_silent() {
    if !gcc_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "silent.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import exchange\nfrom std.binary import size\nprint size(exchange(\"127.0.0.1\", {}, \"PING\", 4, 500))\n",
            listener.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let mut stream = accept_bounded(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING");
            thread::sleep(Duration::from_millis(900));
        }
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    server.join().unwrap();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("TCP exchange timed out"));
    assert!(String::from_utf8_lossy(&native.stderr).contains("TCP exchange timed out"));
}

#[test]
fn native_tcp_exchange_preserves_binary_response_and_enforces_exact_limit() {
    if !gcc_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "binary.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import exchange\nfrom std.binary import size, extract\nfrom std.bytes import to_hex\nfrom std.cli import int as argument_int\nlet reply: Source = exchange(\"127.0.0.1\", {}, \"PING\", argument_int(0), 2000)\nprint to_hex(extract(reply, 0, size(reply)))\n",
            listener.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for _ in 0..4 {
            let mut stream = accept_bounded(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING");
            stream.write_all(&[0, 0xff, b'A', b'B', b'C']).unwrap();
        }
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint, "--", "5"]),
        Duration::from_secs(5),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint, "--", "5"]),
        Duration::from_secs(5),
    );
    let vm_limited = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint, "--", "4"]),
        Duration::from_secs(5),
    );
    let native_limited = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint, "--", "4"]),
        Duration::from_secs(5),
    );
    server.join().unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(vm.stdout, b"00ff414243\n");
    assert_eq!(native.stdout, vm.stdout);
    assert!(!vm_limited.status.success());
    assert!(!native_limited.status.success());
    assert!(String::from_utf8_lossy(&vm_limited.stderr)
        .contains("LimitExceeded: TCP response exceeds 4 bytes"));
    assert!(String::from_utf8_lossy(&native_limited.stderr)
        .contains("LimitExceeded: TCP response exceeds 4 bytes"));
}

#[test]
fn native_tcp_exchange_accepts_ipv6_literal_when_loopback_is_available() {
    if !gcc_available() {
        return;
    }
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        return;
    };
    let endpoint = listener.local_addr().unwrap().to_string();
    let s = Sandbox::new();
    let script = s.write(
        "ipv6.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import exchange\nfrom std.binary import size\nprint size(exchange(\"::1\", {}, \"PING\", 3, 2000))\n",
            listener.local_addr().unwrap().port()
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let mut stream = accept_bounded(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING");
            stream.write_all(b"ACK").unwrap();
        }
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &endpoint]),
        Duration::from_secs(5),
    );
    server.join().unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(vm.stdout, b"3\n");
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_tcp_exchange_resolves_localhost_and_reports_connected_peer() {
    if !gcc_available() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let host_grant = format!("localhost:{port}");
    let address_grant = format!("127.0.0.1:{port}");
    let s = Sandbox::new();
    let script = s.write(
        "localhost.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import exchange\nlet reply: Source = exchange(\"localhost\", {port}, \"PING\", 3, 5000)\nprint reply\n"
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());

    // Grants apply to the requested host, before DNS resolution; an IP grant
    // must not implicitly authorize the hostname that resolves to that IP.
    let vm_denied = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &address_grant]),
        Duration::from_secs(8),
    );
    let native_denied = bounded_output(
        Command::new(&executable).args(["--allow-connect", &address_grant]),
        Duration::from_secs(8),
    );
    for output in [&vm_denied, &native_denied] {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains(&format!("network access not allowed: {host_grant}")));
    }

    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let mut stream = accept_bounded(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING");
            stream.write_all(b"ACK").unwrap();
        }
    });
    let vm = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-connect", &host_grant]),
        Duration::from_secs(8),
    );
    let native = bounded_output(
        Command::new(&executable).args(["--allow-connect", &host_grant]),
        Duration::from_secs(8),
    );
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    server.join().unwrap();
    assert_eq!(native.stdout, vm.stdout);
    let stdout = String::from_utf8_lossy(&native.stdout);
    assert!(stdout.contains(&format!(
        "source(\"tcp://{host_grant}\", origin: \"tcp://{host_grant} (peer {address_grant})\""
    )));
    assert!(stdout.contains(", 3 bytes)"));
}

fn accept_bounded(listener: &TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "test TCP listener timed out");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("test TCP listener failed: {error}"),
        }
    }
}

fn bounded_output(command: &mut Command, timeout: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "TCP client timed out; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn native_python_calls_are_typed_stateful_and_permission_gated() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "count = 0\ndef bump(value):\n    global count\n    count += 1\n    return value + count\ndef upper(value):\n    return value.upper()\ndef even(value):\n    return value % 2 == 0\ndef small():\n    return 7\ndef flip(value):\n    return value[::-1]\n");
    let script = s.write("main.gak", "requires { python.exec }\nimport py.helper\nfrom py.helper import bump as next\nfrom std.bytes import from_hex, to_hex\nfn call(value: i64) -> i64 = next(value)\nlet first: i64 = call(40)\nlet second: i64 = helper.bump(40)\nlet text: str = helper.upper(\"galeikan\")\nlet flag: bool = helper.even(42)\nlet count: u64 = helper.small()\nlet raw: bytes = helper.flip(from_hex(\"41 42\"))\nprint first\nprint second\nprint text\nprint flag\nprint count\nprint to_hex(raw)\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable).output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("--allow-python"));
    let native = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"41\n42\nGALEIKAN\ntrue\n7\n4241\n");
}

#[test]
fn native_python_module_values_match_vm_and_remain_permission_gated() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    let helper = s.write(
        "helper.py",
        "threshold = 41\nlabel = 'Galeikan'\npayload = b'\\x00\\xff'\nnumbers = [3, -2, 9]\ndef bump():\n    global threshold\n    threshold += 1\n    return threshold\n",
    );
    let script = s.write(
        "values.gak",
        "requires { python.exec }\nfrom py.helper import threshold as initial\nimport py.helper as helper\nfrom std.bytes import to_hex\nfrom std.list import count\nlet before: i64 = initial\nlet label: str = helper.label\nlet payload: bytes = helper.payload\nlet numbers: List<i64> = helper.numbers\nlet bumped: i64 = helper.bump()\nfn latest() -> i64 = helper.threshold\nprint before\nprint label\nprint to_hex(payload)\nprint count(numbers)\nprint numbers[1]\nprint bumped\nprint latest()\n",
    );
    let mut expected = None;
    for engine in ["ast", "vm"] {
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-python", python_command()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"41\nGaleikan\n00ff\n3\n-2\n42\n42\n");
        expected = Some(output.stdout);
    }
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable).output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("--allow-python"));
    let native = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, expected.unwrap());

    let wrong_type = s.write(
        "wrong-value.gak",
        "requires { python.exec }\nimport py.helper\nlet threshold: bool = helper.threshold\nprint threshold\n",
    );
    let wrong_build = s.compile(&wrong_type);
    assert!(
        wrong_build.status.success(),
        "{}",
        String::from_utf8_lossy(&wrong_build.stderr)
    );
    let wrong_executable = PathBuf::from(String::from_utf8(wrong_build.stdout).unwrap().trim());
    let wrong = Command::new(wrong_executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr)
        .contains("does not match the declared Galeikan type"));

    fs::write(&helper, "threshold = 99\n").unwrap();
    let changed = Command::new(executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("changed after compilation"));
}

#[test]
fn native_python_module_hash_and_result_types_are_checked() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    let helper = s.write("helper.py", "def number():\n    return 7\n");
    let script = s.write("main.gak", "requires { python.exec }\nimport py.helper\nlet value: i64 = helper.number()\nprint value\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    fs::write(&helper, "def number():\n    return 8\n").unwrap();
    let changed = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("changed after compilation"));
    let wrong = s.write("wrong.gak", "requires { python.exec }\nimport py.helper\nlet value: bool = helper.number()\nprint value\n");
    let built = s.compile(&wrong);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let result = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("does not match the declared Galeikan type"));
}

#[test]
fn native_python_modules_follow_relocated_executable_and_remain_hash_checked() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    let original_helper = s.write(
        "sub/helper.py",
        "def double(value):\n    return value * 2\n",
    );
    s.write(
        "sub/adapter.gak",
        "requires { python.exec }\nimport py.helper\nfn double(value: i64) -> i64 = helper.double(value)\n",
    );
    let script = s.write(
        "main.gak",
        "requires { python.exec }\nimport sub.adapter as adapter\nprint adapter.double(21)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let relocated = s.0.join("relocated Ω");
    fs::create_dir_all(relocated.join("sub")).unwrap();
    let moved_executable = relocated.join(executable.file_name().unwrap());
    fs::copy(&executable, &moved_executable).unwrap();
    let moved_helper = relocated.join("sub/helper.py");
    fs::copy(&original_helper, &moved_helper).unwrap();
    fs::write(&original_helper, "def double(value):\n    return 999\n").unwrap();
    let valid = Command::new(&moved_executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(valid.stdout, b"42\n");
    fs::write(&moved_helper, "def double(value):\n    return 999\n").unwrap();
    let changed = Command::new(&moved_executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("changed after compilation"));
}

#[test]
fn native_python_errors_can_be_captured_as_results() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helper.py",
        "def crash():\n    raise ValueError('sample failed')\n",
    );
    let script = s.write("main.gak", "requires { python.exec }\nimport py.helper\nfrom std.result import is_error, message\nfn checked() -> Result<i64> {\n    let value: i64 = helper.crash()\n    return value\n}\nprint is_error(checked())\nprint message(checked())\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let result = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.starts_with("true\n"), "{output}");
    assert!(
        output.contains("Python call failed: ValueError: sample failed"),
        "{output}"
    );
}

#[test]
fn native_python_import_requires_declared_effect() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "def value():\n    return 7\n");
    let script = s.write(
        "main.gak",
        "import py.helper\nlet value: i64 = helper.value()\nprint value\n",
    );
    let built = s.compile(&script);
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("python.exec was not declared"));
}

#[test]
fn native_local_module_can_call_python_module() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "def double(value):\n    return value * 2\n");
    s.write("adapter.gaks", "requires { python.exec }\nimport py.helper\nfn double(value: i64) -> i64 = helper.double(value)\n");
    let script = s.write(
        "main.gak",
        "requires { python.exec }\nimport adapter\nprint adapter.double(21)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let result = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"42\n");
}

#[test]
fn native_python_call_times_out_without_hanging() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helper.py",
        "import time\ndef slow():\n    time.sleep(30)\n    return 1\n",
    );
    let script = s.write(
        "main.gak",
        "requires { python.exec }\nimport py.helper\nlet value: i64 = helper.slow()\nprint value\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let started = Instant::now();
    let result = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("timed out"));
}

#[test]
fn native_python_homogeneous_lists_roundtrip_like_vm() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "def numbers(values):\n    return [value + 1 for value in values]\ndef unsigned(values):\n    return values[::-1]\ndef flags(values):\n    return [not value for value in values]\ndef words(values):\n    return [value.upper() for value in values]\ndef chunks(values):\n    return [value[::-1] for value in values]\ndef empty(values):\n    return values\n");
    let script = s.write("main.gak", "requires { python.exec }\nimport py.helper\nfrom std.bytes import from_hex, to_hex\nfrom std.list import count\nlet empty_input: List<i64> = []\nlet ints: List<i64> = helper.numbers([1, -2, 3])\nlet uints: List<u64> = helper.unsigned([1u64, 18446744073709551615u64])\nlet bools: List<bool> = helper.flags([true, false])\nlet words: List<str> = helper.words([\"a\", \"weiß\"])\nlet chunks: List<bytes> = helper.chunks([from_hex(\"00 ff\"), from_hex(\"41 42\")])\nlet empty_result: List<i64> = helper.empty(empty_input)\nprint ints\nprint uints\nprint bools\nprint words\nprint to_hex(chunks[0])\nprint to_hex(chunks[1])\nprint count(empty_result)\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            script.to_str().unwrap(),
            "--engine",
            "vm",
            "--allow-python",
            python_command(),
        ])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.ends_with(b"ff00\n4241\n0\n"));
}

#[test]
fn native_python_list_result_rejects_mixed_types() {
    if !gcc_available() || !python_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "def mixed():\n    return [1, 'wrong']\n");
    let script = s.write("main.gak", "requires { python.exec }\nimport py.helper\nlet values: List<i64> = helper.mixed()\nprint values\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .args(["--allow-python", python_command()])
        .output()
        .unwrap();
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&native.stderr)
        .contains("does not match the declared Galeikan type"));
}

#[test]
fn native_executables_have_platform_hardening_signals() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write("hardened.gak", "print 42\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let signals = if cfg!(windows) {
        [
            "pe.dynamic_base",
            "pe.nx_compat",
            "pe.high_entropy_va",
            "pe.section_wx",
        ]
    } else {
        [
            "elf.et_dyn",
            "elf.gnu_stack_nx",
            "elf.relro_now",
            "elf.load_rwx",
        ]
    };
    let mut source = String::from("requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, signal\nfrom std.cli import arg\nlet report = probe(analyze(arg(0), 67108864))\n");
    for name in signals {
        source.push_str(&format!("print signal(report, \"{name}\")\n"));
    }
    let verifier = s.write("verify.gak", &source);
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(verifier)
        .arg("--allow-read")
        .arg(&s.0)
        .arg("--")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"present\npresent\npresent\nabsent\n");
}

#[test]
fn native_empty_lists_keep_their_declared_element_type() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "empty-lists.gak",
        "from std.list import count\nfn empty_numbers() -> List<i64> = []\nlet from_function = empty_numbers()\nlet from_if = if true { [] } else { [5] }\nlet from_match = match 1 { 1 => [], _ => [8] }\nprint count(from_function)\nprint count(from_if)\nprint count(from_match)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"0\n0\n0\n");
}

#[test]
fn native_lists_match_vm_for_indexing_iteration_and_immutable_updates() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "lists.gak",
        "from std.list import append, concat, count\nstruct Marker { label: str, offset: i64 }\nfn total(items: List<i64>) -> i64 {\n    var sum: i64 = 0\n    for item in items {\n        sum = sum + item\n    }\n    return sum\n}\nlet empty: List<i64> = []\nlet values = concat([1, 2], append(empty, 3))\nvar stored: List<i64> = [9]\nlet original = stored\nlet words: List<str> = [\"weiß\", \"研究🔍\"]\nlet markers: List<Marker> = [Marker(\"MZ\", 0), Marker(\"ELF\", 4)]\nstored = append(stored, 10)\nprint total(values)\nprint values[2]\nprint count(values)\nprint count(original)\nprint stored[1]\nfor word in words {\n    print word\n}\nprint markers[1].label\nfor marker in markers {\n    print marker.offset\n}\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        native.stdout,
        "6\n3\n3\n1\n10\nweiß\n研究🔍\nELF\n0\n4\n".as_bytes()
    );
    for (name, index) in [("negative", -1), ("past-end", 1)] {
        let invalid = s.write(
            &format!("list-{name}.gak"),
            &format!("let items: List<i64> = [7]\nprint items[{index}]\n"),
        );
        let compiled = s.compile(&invalid);
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&native.stderr).contains("list index out of range"));
    }
}

#[test]
fn native_string_equality_compares_contents_like_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "strings.gak",
        "let first: str = \"Galeikan\"\nlet second: str = \"Galeikan\"\nlet other: str = \"GaleikanScript\"\nprint first == second\nprint first != second\nprint first == other\nprint first != other\nprint \"weiß\" == \"weiß\"\nprint if first == second { 42 } else { 0 }\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"true\nfalse\nfalse\ntrue\ntrue\n42\n");
}

#[test]
fn native_strings_preserve_embedded_nul_bytes_like_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "nul-strings.gak",
        "let first = \"A\0B\"\nlet second = \"A\0C\"\nprint 42\nprint first\nprint first == \"A\0B\"\nprint first == second\nprint first != second\nprint match first { \"A\0B\" => 7, _ => 0 }\nprint \"\"\nprint true\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"42\nA\0B\ntrue\nfalse\ntrue\n7\n\ntrue\n");
}

#[test]
fn native_results_match_vm_for_construction_recovery_and_propagation() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "results.gak",
        "from std.result import ok, fail, is_ok, is_error, message, recover\nfn gate(n: i64) -> Result<i64> = if n < 0 { fail(\"negative\") } else { ok(n) }\nfn bump(n: i64) -> Result<i64> {\n    let checked: i64 = gate(n)?\n    return checked + 1\n}\nfn forward(value: Result<i64>) -> Result<i64> = value\nlet good: Result<i64> = forward(gate(4))\nlet bad: Result<i64> = gate(-1)\nprint is_ok(good)\nprint is_error(bad)\nprint message(bad)\nprint recover(bad, 7)\nprint recover(good, 7)\nprint bump(4)?\nprint message(bump(-1))\nprint ok(\"A\0B\")\nprint fail(\"oops\")\nprint ok(true)\nprint ok(18446744073709551615u64)\nprint recover(fail(\"x\"), \"fallback\")\nprint true\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native
        .stdout
        .starts_with(b"true\ntrue\nnegative\n7\n4\n5\n"));
    assert!(native
        .stdout
        .ends_with(b"ok(A\0B)\nerror(oops)\nok(true)\nok(18446744073709551615)\nfallback\ntrue\n"));
}

#[test]
fn native_print_formats_lists_records_and_record_results_like_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "compound-print.gak",
        "from std.result import ok, fail\nstruct Item { name: str, offsets: List<i64> }\nstruct Wrapper { item: Result<Item> }\nfn missing() -> Result<Item> = fail(\"missing\")\nlet item = Item(\"A\0B\", [1, 2])\nprint item\nprint [Item(\"x\", [3]), Item(\"y\", [])]\nprint [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]\nprint ok(item)\nprint Wrapper(ok(item))\nprint missing()\nprint []\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native
        .stdout
        .starts_with(b"Item(name: A\0B, offsets: [1, 2])\n"));
    assert!(native.stdout.ends_with(
        b"ok(Item(name: A\0B, offsets: [1, 2]))\nWrapper(item: ok(Item(name: A\0B, offsets: [1, 2])))\nerror(missing)\n[]\n"
    ));
}

#[test]
fn native_result_functions_capture_arithmetic_errors_like_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "result-arithmetic.gak",
        "from std.result import is_error, message\nfn divide() -> Result<i64> = 1 / 0\nfn overflow() -> Result<i64> {\n    let value = 9223372036854775807 + 1\n    return value\n}\nprint is_error(divide())\nprint message(divide())\nprint is_error(overflow())\nprint message(overflow())\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_result_functions_capture_result_api_errors_like_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "result-api-errors.gak",
        "from std.result import ok, fail, is_error, message\nfn empty() -> Result<i64> = fail(\"\")\nfn nul() -> Result<i64> = fail(\"a\0b\")\nfn success_message() -> Result<str> = message(ok(1))\nprint is_error(empty())\nprint message(empty())\nprint is_error(nul())\nprint message(nul())\nprint is_error(success_message())\nprint message(success_message())\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_nested_result_errors_keep_module_and_action_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helper.gak",
        "fn raw() -> i64 {\n    let value = 1 / 0\n    return value\n}\nfn checked() -> Result<i64> {\n    let value = raw()\n    return value\n}\n",
    );
    let script = s.write(
        "nested-result.gak",
        "import helper\nfrom std.result import message\nprint message(helper.checked())\nprint helper.checked()?\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(!vm.status.success());
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(!native.status.success());
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stderr, vm.stderr);
}

#[test]
fn native_uncaught_runtime_errors_keep_action_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, source) in [
        ("direct-error.gak", "print 1 / 0\n"),
        (
            "nested-error.gak",
            "fn raw() -> i64 {\n    let value = 1 / 0\n    return value\n}\nprint raw()\n",
        ),
    ] {
        let script = s.write(name, source);
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout);
        assert_eq!(native.stderr, vm.stderr);
    }
}

#[test]
fn native_numeric_cli_arguments_match_vm_across_imports_and_boundaries() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helper.gak",
        "from std.cli import count as arguments\nfn amount() -> i64 = arguments()\n",
    );
    let script = s.write(
        "cli.gak",
        "import helper\nfrom std.cli import int as number\nfrom std.cli import arg as text\nprint helper.amount()\nprint number(0)\nprint number(1)\nprint text(2)\nprint text(2) == text(2)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    for args in [
        ["12", "-3", "Galeikan"],
        [
            "+9223372036854775807",
            "-9223372036854775808",
            "Pfad mit äöü",
        ],
        ["0007", "-0", "研究🔍"],
    ] {
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            vm.status.success(),
            "{}",
            String::from_utf8_lossy(&vm.stderr)
        );
        let native = Command::new(&executable).args(args).output().unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout);
    }
    for args in [
        vec!["not-a-number", "1", "ok"],
        vec!["9223372036854775808", "1", "ok"],
        vec!["-9223372036854775809", "1", "ok"],
        vec!["+", "1", "ok"],
        vec!["1", "2"],
        vec!["1"],
        vec![],
    ] {
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--"])
            .args(&args)
            .output()
            .unwrap();
        let native = Command::new(&executable).args(&args).output().unwrap();
        assert!(!vm.status.success(), "{args:?}");
        assert!(!native.status.success(), "{args:?}");
    }
    let bad_index = s.write("cli-bad-index.gak", "import std.cli\nprint cli.arg(-1)\n");
    let built = s.compile(&bad_index);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&native.stderr).contains("argument index out of range"));
}

#[test]
fn native_unsigned_64_bit_values_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "unsigned.gak",
        "let max: u64 = 18446744073709551615u64\nprint max\nprint ~0u64\nprint max > 9223372036854775807u64\nprint 0x8000000000000000u64 >> 63u64\nprint 3u64 * 7u64\nprint match max { 0xffffffffffffffffu64 => 1, _ => 0 }\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_match_expression_matches_vm_and_evaluates_subject_once() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "match.gaks",
        "fn code() -> i64 {\n    print 90\n    return 0x5a\n}\nprint match code() {\n    0x4d => 1 / 0,\n    0x5a => 7,\n    _ => 0,\n}\nprint match \"ELF\" { \"MZ\" => 0, \"ELF\" => 2, _ => 3 }\nprint match true { false => 0, _ => 1 }\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"90\n7\n2\n1\n");
}

#[test]
fn native_bitwise_operations_match_vm_and_reject_invalid_shifts() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "bits.gaks",
        "print 0xffffffffffffffff\nprint ~0\nprint 0x8000000000000000 >>> 63\nprint -8 >> 2\nprint 1 << 63\nprint 0xf0 & 0x3c | 0x80 ^ 0x01\nprint 1 + 2 << 3\nprint 4 & 3 == 0\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    for (index, source) in ["print 1 << 64\n", "print 1 >>> -1\n"].iter().enumerate() {
        let bad = s.write(&format!("invalid-{index}.gak"), source);
        let compiled = s.compile(&bad);
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
        let result = Command::new(executable).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("shift count must be in 0..63"));
    }
}

#[test]
fn native_class_methods_match_vm_across_modules_and_nested_fields() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "model.gaks",
        "class Point {\n    x: i64\n    y: i64\n    fn sum() -> i64 = self.x + self.y\n    fn shift(dx: i64, dy: i64) -> Point = Point(self.x + dx, self.y + dy)\n}\nfn build() -> Point {\n    print 99\n    return Point(1, 2)\n}\nlet origin = Point(1, 1)\n",
    );
    let script = s.write(
        "main.gak",
        "import model\nclass Tagged {\n    point: model.Point\n    label: str\n    fn total() -> i64 = self.point.sum()\n}\nlet first = model.Point(3, 4)\nlet second = first.shift(2, 5)\nlet tagged = Tagged(second, \"ok\")\nprint first.sum()\nprint second.sum()\nprint tagged.point.sum()\nprint tagged.total()\nprint model.Point(10, 1).sum()\nprint first.shift(1, 1).sum()\nprint model.build().sum()\nprint model.origin.sum()\n",
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = if cfg!(windows) {
        script.with_extension("gak.exe")
    } else {
        script.with_extension("gak.native")
    };
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        "7\n14\n14\n14\n11\n9\n99\n3\n2\n"
    );
}

#[test]
fn native_break_and_continue_match_vm_in_nested_loops_and_functions() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "loops.gaks",
        "import std.iter\nvar total = 0\nfn count(limit: i64) -> i64 {\n    var index = 0\n    var sum = 0\n    while index < limit {\n        index = index + 1\n        if index == 2 {\n            continue\n        }\n        if index == 4 {\n            break\n        }\n        sum = sum + index\n    }\n    return sum\n}\nfor outer in iter.range(4) {\n    if outer == 3 {\n        break\n    }\n    for inner in iter.range(5) {\n        if inner == 1 {\n            continue\n        }\n        if inner == 4 {\n            break\n        }\n        total = total + outer * 10 + inner\n    }\n}\nprint total\nprint count(7)\n",
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = if cfg!(windows) {
        script.with_extension("gaks.exe")
    } else {
        script.with_extension("gaks.native")
    };
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(String::from_utf8_lossy(&native.stdout), "105\n4\n");
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("galeikan-native-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, source: &str) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, source).unwrap();
        path
    }

    fn compile(&self, path: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("compile")
            .arg(path)
            .output()
            .unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn gcc_available() -> bool {
    Command::new("gcc").arg("--version").output().is_ok()
}

#[test]
fn native_structs_match_vm_across_modules_calls_and_field_access() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "model.gaks",
        "struct Header { marker: str, offset: i64 }\nfn make(offset: i64) -> Header = Header(\"MZ\", offset)\n",
    );
    let script = s.write(
        "main.gak",
        "import model\nfrom model import Header as H\nstruct Tagged { header: model.Header, verified: bool }\nfn tag(value: model.Header) -> Tagged = Tagged(value, true)\nvar first: H = model.make(4)\nlet second = model.make(8)\nprint first.marker\nprint second.offset\nfirst = H(\"ELF\", 16)\nprint tag(first).header.marker\nprint tag(first).verified\nprint second.marker\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.0.join("model.gaks")).unwrap();
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"MZ\n8\nELF\ntrue\nMZ\n");
}

#[test]
fn native_struct_allocations_stop_at_the_corpus_limit() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let fields = (0..64)
        .map(|index| format!("field{index}: i64"))
        .collect::<Vec<_>>()
        .join(", ");
    let values = vec!["0"; 64].join(", ");
    let script = s.write(
        "bounded.gak",
        &format!(
            "struct Block {{ {fields} }}\nvar index = 0\nwhile index < 131073 {{\n    let item = Block({values})\n    index = index + 1\n}}\n"
        ),
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let output = Command::new(executable).output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("native struct memory exceeds 64 MiB"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_compiler_accepts_gaks_entry_and_local_module() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.gaks", "fn twice(value: i64) -> i64 = value * 2\n");
    let script = s.write("main.gaks", "import helper\nprint helper.twice(21)\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    assert_eq!(
        executable,
        script.with_extension(if cfg!(windows) {
            "gaks.exe"
        } else {
            "gaks.native"
        })
    );
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.0.join("helper.gaks")).unwrap();
    let output = Command::new(executable).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"42\n");
}

#[test]
fn native_typed_bindings_match_vm_and_reject_wrong_types() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "typed.gak",
        "var total: i64 = 0\nfn sum(end: i64) -> i64 {\n    var index: i64 = 0\n    var result: i64 = 0\n    while index < end {\n        let item: i64 = index + 1\n        result = result + item\n        index = index + 1\n    }\n    return result\n}\ntotal = sum(3)\nprint total\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(vm.stdout, b"6\n");
    let build = s.compile(&script);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);

    let invalid = s.write("invalid.gak", "let value: bool = 1\nprint value\n");
    let output = s.compile(&invalid);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("binding value"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_else_if_chain_matches_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "decision_chain.gak",
        include_str!("../examples/decision_chain.gak"),
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_conditional_action_blocks_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "conditional_actions.gak",
        include_str!("../examples/conditional_actions.gak"),
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_early_returns_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "early_return.gak",
        include_str!("../examples/early_return.gak"),
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_exhaustive_returns_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "exhaustive_return.gak",
        include_str!("../examples/exhaustive_return.gak"),
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_from_import_reads_local_module_values() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write("config.gak", "let base: i64 = 40\n");
    let script = s.write(
        "main.gak",
        "from config import base as start\nprint start + 2\n",
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let out = Command::new(executable).output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"42\n");
}

#[test]
fn native_scalar_program_matches_vm_and_runs_without_source() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "main.gak",
        "var index = 0\nvar total = 0\nwhile index < 4 {\n    total = total + index\n    print if index == 0 { \"start\" } else { \"next\" }\n    index = index + 1\n}\nprint total\nprint 100 / 5 / 2\nprint true and not false\nprint false and 1 / 0 == 0\nprint true or 1 / 0 == 0\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let build = s.compile(&script);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
    assert!(executable.is_file());
    let native = Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    fs::remove_file(&script).unwrap();
    assert_eq!(
        Command::new(&executable).output().unwrap().stdout,
        vm.stdout
    );
}

#[test]
fn native_scalar_functions_match_vm_with_locals_and_nested_calls() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "functions.gak",
        "var base = 10\nfn twice(n: i64) -> i64 = n * 2\nfn add_base(n: i64) -> i64 = n + base\nfn countdown(n: i64) -> i64 {\n    var current = n\n    var total = 0\n    while current > 0 {\n        total = total + current\n        current = current - 1\n    }\n    return total\n}\nfn greet(flag: bool) -> str = if flag { \"yes\" } else { \"no\" }\nfn noisy(n: i64) -> i64 {\n    print \"inside\"\n    return n + 1\n}\nprint twice(21)\nprint add_base(5)\nbase = 20\nprint add_base(5)\nprint countdown(4)\nprint greet(true)\nprint 3 + noisy(4)\nprint twice(twice(2))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let build = s.compile(&script);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
    let native = Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    fs::remove_file(&script).unwrap();
    assert_eq!(
        Command::new(&executable).output().unwrap().stdout,
        vm.stdout
    );
}

#[test]
fn native_local_modules_match_vm_and_run_without_sources() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let core = s.write(
        "core.gak",
        "var bias = 3\nfn bump(n: i64) -> i64 = n + bias\nfn set_bias(n: i64) -> i64 {\n    bias = n\n    return bias\n}\n",
    );
    let math = s.write(
        "tools/math.gak",
        "import \"../core.gak\" as c\nlet start = c.bias\nfn triple(n: i64) -> i64 = (c.bump(n) + start) * 3\n",
    );
    let script = s.write(
        "modules.gak",
        "import core\nfrom tools.math import triple\nprint triple(2)\nprint core.bias\nprint core.set_bias(10)\nprint triple(2)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(vm.stdout, b"24\n3\n10\n45\n");
    let build = s.compile(&script);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
    let native = Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    fs::remove_file(script).unwrap();
    fs::remove_file(core).unwrap();
    fs::remove_file(math).unwrap();
    assert_eq!(Command::new(executable).output().unwrap().stdout, vm.stdout);
}

#[test]
fn native_locked_package_matches_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":1,\"dependencies\":{\"math\":\"vendor/math\"}}\n",
    );
    s.write("vendor/math/main.gak", "fn twice(n: i64) -> i64 = n * 2\n");
    let script = s.write(
        "main.gak",
        "import pkg.math as math\nprint math.twice(21)\n",
    );
    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let build = s.compile(&script);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
    let native = Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"42\n");
}

#[test]
fn native_versioned_transitive_package_matches_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":2,\"dependencies\":{\"math\":{\"path\":\"vendor/math\",\"version\":\"1.0.0\"}}}\n",
    );
    s.write(
        "vendor/math/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"math\",\"version\":\"1.0.0\"},\"dependencies\":{\"core\":{\"path\":\"vendor/core\",\"version\":\"0.2.0\"}}}\n",
    );
    s.write(
        "vendor/core/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"core\",\"version\":\"0.2.0\"},\"dependencies\":{}}\n",
    );
    s.write("vendor/core/main.gak", "fn twice(n: i64) -> i64 = n * 2\n");
    s.write(
        "vendor/math/main.gak",
        "import pkg.core\nfn answer() -> i64 = core.twice(21)\n",
    );
    let script = s.write("main.gak", "import pkg.math\nprint math.answer()\n");
    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let compiled = s.compile(&script);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"42\n");
}

#[test]
fn native_recursive_functions_match_vm_and_limit_call_depth() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "recursive.gak",
        "fn factorial(n: i64) -> i64 {\n    if n <= 1 {\n        return 1\n    }\n    return n * factorial(n - 1)\n}\nprint factorial(6)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"720\n");

    let endless = s.write(
        "endless.gak",
        "fn again(n: i64) -> i64 = again(n)\nprint again(1)\n",
    );
    let built = s.compile(&endless);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let output = Command::new(executable).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("call depth exceeded"));
}

#[test]
fn native_mutual_recursion_matches_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "mutual.gak",
        "fn even(n: i64) -> bool = if n == 0 { true } else { odd(n - 1) }\nfn odd(n: i64) -> bool = if n == 0 { false } else { even(n - 1) }\nprint even(12)\nprint odd(13)\nprint even(13)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"true\ntrue\nfalse\n");
}

#[test]
fn native_recursive_result_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "recursive-result.gak",
        "from std.result import fail, is_error, message, recover\nfn descend(n: i64) -> Result<i64> {\n    if n == 0 {\n        return fail(\"bottom\")\n    }\n    let value: i64 = descend(n - 1)?\n    return value + 1\n}\nprint is_error(descend(3))\nprint message(descend(3))\nprint recover(descend(3), 9)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(b"true\n"));
    assert!(native.stdout.ends_with(b"bottom\n9\n"));
}

#[test]
fn native_arithmetic_and_loop_limits_fail_closed() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, source, message) in [
        (
            "overflow",
            "print 9223372036854775807 + 1\n",
            "integer overflow",
        ),
        ("division", "print 5 / 0\n", "division by zero"),
        (
            "limit",
            "while true {\n}\n",
            "execution exceeds 1000000 action steps",
        ),
        (
            "function_overflow",
            "fn bump(n: i64) -> i64 = n + 1\nprint bump(9223372036854775807)\n",
            "integer overflow",
        ),
        (
            "function_limit",
            "fn spin() -> i64 {\n    while true {\n    }\n    return 1\n}\nprint spin()\n",
            "execution exceeds 1000000 action steps",
        ),
    ] {
        let script = s.write(&format!("{name}.gak"), source);
        let build = s.compile(&script);
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(build.stdout).unwrap().trim());
        let result = Command::new(executable).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(message));
    }
}

#[test]
fn native_range_loops_match_vm_across_local_module_and_nested_calls() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let helper = s.write(
        "helper.gak",
        "from std.iter import range as indices\nfn score(start: i64, end: i64) -> i64 {\n    var total: i64 = 0\n    for outer in indices(start, end) {\n        for inner in indices(2) {\n            total = total + outer + inner\n        }\n    }\n    return total\n}\n",
    );
    let script = s.write(
        "range.gak",
        "import helper\nfrom std.iter import range\nvar calls = 0\nvar total = 0\nfn endpoint() -> i64 {\n    calls = calls + 1\n    return 4\n}\nprint helper.score(1, endpoint())\nprint calls\nfor index in range(3, 6) {\n    total = total + index\n}\nfor skipped in range(5, 2) {\n    total = total + 1000\n}\nprint total\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(vm.stdout, b"15\n1\n12\n");
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    fs::remove_file(&script).unwrap();
    fs::remove_file(helper).unwrap();
    assert_eq!(Command::new(executable).output().unwrap().stdout, vm.stdout);
}

#[test]
fn native_range_rejects_invalid_bounds_and_oversized_sequences_at_runtime() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, call, expected) in [
        (
            "negative-start",
            "range(-1, 2)",
            "range start must not be negative",
        ),
        (
            "negative-end",
            "range(0, -1)",
            "range end must not be negative",
        ),
        ("too-many", "range(0, 100001)", "range exceeds 100000 items"),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!("from std.iter import range\nfor item in {call} {{\n    print item\n}}\n"),
        );
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&native.stderr).contains(expected));
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .arg("--engine")
            .arg("vm")
            .output()
            .unwrap();
        assert!(!vm.status.success());
        assert!(String::from_utf8_lossy(&vm.stderr).contains(expected));
    }
}

#[test]
fn native_compiler_rejects_unsupported_modules() {
    let s = Sandbox::new();
    let script = s.write("module.gak", "import std.asm\nprint 42\n");
    let result = s.compile(&script);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("native compiler does not yet support standard or Python module std.asm"));
}

#[test]
fn native_elf32_rel_and_rela_match_vm_in_both_byte_orders() {
    if !gcc_available() {
        return;
    }
    fn put16(bytes: &mut [u8], at: usize, value: u16, big: bool) {
        bytes[at..at + 2].copy_from_slice(&if big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }
    fn put32(bytes: &mut [u8], at: usize, value: u32, big: bool) {
        bytes[at..at + 4].copy_from_slice(&if big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }
    let s = Sandbox::new();
    let file = s.0.join("relocations32.elf");
    let script = s.write(
        "elf32_relocations.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, relocation_count, relocation_location, relocation_address, relocation_type, relocation_kind, relocation_summary, relocation_symbol, relocation_addend\nfrom std.result import is_error, recover\nlet report: Format = probe(analyze(\"relocations32.elf\", 4096))\nfn addend() -> Result<i64> = relocation_addend(report, 0)\nprint relocation_count(report)\nprint relocation_location(report)\nprint relocation_summary(report, 0)\nprint relocation_address(report, 0)\nprint relocation_type(report, 0)\nprint relocation_kind(report, 0)\nprint relocation_symbol(report, 0)\nprint is_error(addend())\nprint recover(addend(), 0)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    for big in [false, true] {
        for rela in [false, true] {
            let mut bytes = vec![0u8; 0x200];
            bytes[..4].copy_from_slice(b"\x7fELF");
            bytes[4..7].copy_from_slice(&[1, if big { 2 } else { 1 }, 1]);
            put16(&mut bytes, 16, 1, big);
            put16(&mut bytes, 18, 3, big);
            put32(&mut bytes, 20, 1, big);
            put32(&mut bytes, 32, 0x80, big);
            put16(&mut bytes, 40, 52, big);
            put16(&mut bytes, 46, 40, big);
            put16(&mut bytes, 48, 2, big);
            let section = 0xa8;
            let entry_size = if rela { 12 } else { 8 };
            put32(&mut bytes, section + 4, if rela { 4 } else { 9 }, big);
            put32(&mut bytes, section + 16, 0x150, big);
            put32(&mut bytes, section + 20, entry_size, big);
            put32(&mut bytes, section + 36, entry_size, big);
            put32(&mut bytes, 0x150, 0x10, big);
            put32(&mut bytes, 0x154, (2 << 8) | 1, big);
            if rela {
                put32(&mut bytes, 0x158, u32::MAX - 3, big);
            }
            fs::write(&file, bytes).unwrap();
            let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("run")
                .arg(&script)
                .args(["--engine", "vm", "--allow-read"])
                .arg(&s.0)
                .output()
                .unwrap();
            let native = Command::new(&executable)
                .arg("--allow-read")
                .arg(&s.0)
                .output()
                .unwrap();
            assert!(
                vm.status.success(),
                "{}",
                String::from_utf8_lossy(&vm.stderr)
            );
            assert!(
                native.status.success(),
                "{}",
                String::from_utf8_lossy(&native.stderr)
            );
            assert_eq!(native.stdout, vm.stdout);
            let output = String::from_utf8_lossy(&native.stdout);
            assert!(output.starts_with("1\nsection_offset\n"));
            assert!(output.ends_with(if rela { "false\n-4\n" } else { "true\n0\n" }));
        }
    }
}

#[test]
fn native_elf_relr_matches_vm_with_sections_dynamic_tags_and_bitmap_errors() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut bytes = vec![0u8; 0x500];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x300u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x300u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&2u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x120u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400120u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&64u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&64u64.to_le_bytes());
    for (index, (tag, value)) in [(36u64, 0x400280u64), (35, 24), (37, 8), (0, 0)]
        .into_iter()
        .enumerate()
    {
        let at = 0x120 + index * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (index, entry) in [0x405000u64, 0b1011, 0b101].into_iter().enumerate() {
        let at = 0x280 + index * 8;
        bytes[at..at + 8].copy_from_slice(&entry.to_le_bytes());
    }
    let file = s.0.join("relr.elf");
    let script = s.write(
        "relr.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, relocation_count, relocation_location, relocation_address, relocation_kind, relocation_summary, relocation_type, relocation_symbol\nfrom std.iter import range\nfrom std.result import is_error, message\nlet report: Format = probe(analyze(\"relr.elf\", 4096))\nfn missing_type() -> Result<i64> = relocation_type(report, 0)\nfn missing_symbol() -> Result<i64> = relocation_symbol(report, 0)\nprint relocation_count(report)\nprint relocation_location(report)\nfor index in range(relocation_count(report)) {\n    print relocation_summary(report, index)\n    print relocation_address(report, index)\n    print relocation_kind(report, index)\n}\nprint is_error(missing_type())\nprint message(missing_type())\nprint is_error(missing_symbol())\nprint message(missing_symbol())\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    for section in [false, true] {
        let mut variant = bytes.clone();
        if section {
            variant[40..48].copy_from_slice(&0x300u64.to_le_bytes());
            variant[58..60].copy_from_slice(&64u16.to_le_bytes());
            variant[60..62].copy_from_slice(&2u16.to_le_bytes());
            variant[0x344..0x348].copy_from_slice(&19u32.to_le_bytes());
            variant[0x358..0x360].copy_from_slice(&0x280u64.to_le_bytes());
            variant[0x360..0x368].copy_from_slice(&24u64.to_le_bytes());
            variant[0x378..0x380].copy_from_slice(&8u64.to_le_bytes());
        }
        fs::write(&file, variant).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(
            vm.status.success(),
            "{}",
            String::from_utf8_lossy(&vm.stderr)
        );
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout);
        let output = String::from_utf8_lossy(&native.stdout);
        assert!(output.starts_with("4\nva\nRELR_RELATIVE @ va 0x405000\n"));
        assert!(output.contains("RELR_RELATIVE @ va 0x405208\n"));
        assert!(output.ends_with("true\nRELR relocation has no raw type code\ntrue\nRELR relocation has no symbol index\n"));
    }
    let mut malformed = bytes.clone();
    malformed[0x280..0x288].copy_from_slice(&3u64.to_le_bytes());
    fs::write(&file, malformed).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("ELF RELR bitmap without address"));
    assert!(String::from_utf8_lossy(&native.stderr).contains("ELF RELR bitmap without address"));
}

#[test]
fn native_elf_relocations_match_vm_from_sections_and_dynamic_tables() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut bytes = vec![0u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x200u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x200u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&2u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x120u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400120u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&128u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&128u64.to_le_bytes());
    for (index, (tag, value)) in [
        (7u64, 0x400200u64),
        (8, 48),
        (9, 24),
        (23, 0x400230),
        (2, 24),
        (20, 7),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x120 + index * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (index, (address, info, addend)) in [
        (0x404000u64, 8u64, 0x1234i64),
        (0x404008, (1u64 << 32) | 6, -1),
        (0x404010, (2u64 << 32) | 7, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x200 + index * 24;
        bytes[at..at + 8].copy_from_slice(&address.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&info.to_le_bytes());
        bytes[at + 16..at + 24].copy_from_slice(&addend.to_le_bytes());
    }
    let file = s.0.join("relocations.elf");
    let script = s.write(
        "elf_relocations.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, relocation_count, relocation_location, relocation_rva, relocation_address, relocation_type, relocation_kind, relocation_summary, relocation_symbol, relocation_addend\nfrom std.iter import range\nfrom std.result import is_error, message\nlet report: Format = probe(analyze(\"relocations.elf\", 4096))\nfn no_rva() -> Result<i64> = relocation_rva(report, 0)\nprint relocation_count(report)\nprint relocation_location(report)\nfor index in range(relocation_count(report)) {\n    print relocation_summary(report, index)\n    print relocation_address(report, index)\n    print relocation_type(report, index)\n    print relocation_kind(report, index)\n    print relocation_symbol(report, index)\n    print relocation_addend(report, index)\n}\nprint is_error(no_rva())\nprint message(no_rva())\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    for sections in [false, true] {
        let mut variant = bytes.clone();
        if sections {
            variant[40..48].copy_from_slice(&0x300u64.to_le_bytes());
            variant[58..60].copy_from_slice(&64u16.to_le_bytes());
            variant[60..62].copy_from_slice(&3u16.to_le_bytes());
            for (index, (offset, size)) in [(0x200u64, 48u64), (0x230, 24)].into_iter().enumerate()
            {
                let at = 0x340 + index * 64;
                variant[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes());
                variant[at + 24..at + 32].copy_from_slice(&offset.to_le_bytes());
                variant[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
                variant[at + 56..at + 64].copy_from_slice(&24u64.to_le_bytes());
            }
        }
        fs::write(&file, &variant).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(
            vm.status.success(),
            "{}",
            String::from_utf8_lossy(&vm.stderr)
        );
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout);
        let output = String::from_utf8_lossy(&native.stdout);
        assert!(output.starts_with("3\nva\nR_X86_64_RELATIVE @ va 0x404000\n"));
        assert!(output.contains("R_X86_64_GLOB_DAT @ va 0x404008\n"));
        assert!(output.contains("\n-1\n"));
        assert!(output.ends_with("true\nrelocation_rva requires a PE image\n"));
    }
    for (offset, value, error) in [
        (
            0x120 + 2 * 16 + 8,
            8u64,
            "invalid ELF relocation entry size",
        ),
        (0x120 + 3 * 16, 7, "duplicate ELF relocation dynamic tag"),
        (
            0x120 + 2 * 16,
            42,
            "incomplete ELF dynamic relocation table",
        ),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        fs::write(&file, invalid).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(!vm.status.success());
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&vm.stderr).contains(error));
        assert!(String::from_utf8_lossy(&native.stderr).contains(error));
    }
}

fn elf_dynamic_symbol_fixture(sections: bool, gnu_hash: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x500];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x400u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x400u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&2u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x120u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400120u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&112u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&112u64.to_le_bytes());
    for (index, (tag, value)) in [
        (6u64, 0x400200u64),
        (11, 24),
        (5, 0x400280),
        (10, 14),
        (
            if gnu_hash { 0x6fff_fef5 } else { 4 },
            if gnu_hash { 0x400320 } else { 0x400300 },
        ),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x120 + index * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (index, (name, info, section, address, size)) in [
        (0u32, 0u8, 0u16, 0u64, 0u64),
        (1, 0x12, 0, 0, 0),
        (6, 0x12, 1, 0x401000, 12),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x200 + index * 24;
        bytes[at..at + 4].copy_from_slice(&name.to_le_bytes());
        bytes[at + 4] = info;
        bytes[at + 6..at + 8].copy_from_slice(&section.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&address.to_le_bytes());
        bytes[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
    }
    bytes[0x280..0x28e].copy_from_slice(b"\0puts\0inspect\0");
    bytes[0x300..0x304].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x304..0x308].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x308..0x30c].copy_from_slice(&1u32.to_le_bytes());
    for (index, value) in [1u32, 1, 1, 5].into_iter().enumerate() {
        bytes[0x320 + index * 4..0x324 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x338..0x33c].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x33c..0x340].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[0x340..0x344].copy_from_slice(&0x101u32.to_le_bytes());
    if sections {
        bytes[40..48].copy_from_slice(&0x380u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
        let dynsym = 0x380 + 64;
        bytes[dynsym + 4..dynsym + 8].copy_from_slice(&11u32.to_le_bytes());
        bytes[dynsym + 24..dynsym + 32].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[dynsym + 32..dynsym + 40].copy_from_slice(&72u64.to_le_bytes());
        bytes[dynsym + 40..dynsym + 44].copy_from_slice(&2u32.to_le_bytes());
        bytes[dynsym + 56..dynsym + 64].copy_from_slice(&24u64.to_le_bytes());
        let dynstr = 0x380 + 128;
        bytes[dynstr + 4..dynstr + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[dynstr + 24..dynstr + 32].copy_from_slice(&0x280u64.to_le_bytes());
        bytes[dynstr + 32..dynstr + 40].copy_from_slice(&14u64.to_le_bytes());
    }
    bytes
}

fn elf32_be_dynamic_symbol_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x300];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[1, 2, 1]);
    bytes[16..18].copy_from_slice(&3u16.to_be_bytes());
    bytes[18..20].copy_from_slice(&3u16.to_be_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&52u32.to_be_bytes());
    bytes[40..42].copy_from_slice(&52u16.to_be_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_be_bytes());
    bytes[44..46].copy_from_slice(&2u16.to_be_bytes());
    for (index, (kind, offset, va, size)) in [
        (1u32, 0x100u32, 0x1000u32, 0x200u32),
        (2, 0x120, 0x1020, 48),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 52 + index * 32;
        bytes[at..at + 4].copy_from_slice(&kind.to_be_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&offset.to_be_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&va.to_be_bytes());
        bytes[at + 16..at + 20].copy_from_slice(&size.to_be_bytes());
        bytes[at + 20..at + 24].copy_from_slice(&size.to_be_bytes());
        bytes[at + 24..at + 28].copy_from_slice(&5u32.to_be_bytes());
    }
    for (index, (tag, value)) in [
        (6u32, 0x1080u32),
        (11, 16),
        (5, 0x10c0),
        (10, 14),
        (4, 0x10e0),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x120 + index * 8;
        bytes[at..at + 4].copy_from_slice(&tag.to_be_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    for (index, (name, section, address)) in [(0u32, 0u16, 0u32), (1, 0, 0), (6, 1, 0x2000)]
        .into_iter()
        .enumerate()
    {
        let at = 0x180 + index * 16;
        bytes[at..at + 4].copy_from_slice(&name.to_be_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&address.to_be_bytes());
        bytes[at + 12] = if index == 0 { 0 } else { 0x12 };
        bytes[at + 14..at + 16].copy_from_slice(&section.to_be_bytes());
    }
    bytes[0x1c0..0x1ce].copy_from_slice(b"\0puts\0inspect\0");
    bytes[0x1e0..0x1e4].copy_from_slice(&1u32.to_be_bytes());
    bytes[0x1e4..0x1e8].copy_from_slice(&3u32.to_be_bytes());
    bytes
}

fn elf_static_symbol_fixture() -> Vec<u8> {
    let mut bytes = elf_dynamic_symbol_fixture(true, false);
    bytes.resize(0x600, 0);
    bytes[60..62].copy_from_slice(&5u16.to_le_bytes());
    let symtab = 0x380 + 3 * 64;
    bytes[symtab + 4..symtab + 8].copy_from_slice(&2u32.to_le_bytes());
    bytes[symtab + 24..symtab + 32].copy_from_slice(&0x500u64.to_le_bytes());
    bytes[symtab + 32..symtab + 40].copy_from_slice(&96u64.to_le_bytes());
    bytes[symtab + 40..symtab + 44].copy_from_slice(&4u32.to_le_bytes());
    bytes[symtab + 56..symtab + 64].copy_from_slice(&24u64.to_le_bytes());
    let strtab = 0x380 + 4 * 64;
    bytes[strtab + 4..strtab + 8].copy_from_slice(&3u32.to_le_bytes());
    bytes[strtab + 24..strtab + 32].copy_from_slice(&0x580u64.to_le_bytes());
    bytes[strtab + 32..strtab + 40].copy_from_slice(&21u64.to_le_bytes());
    for (index, (name, info, visibility, section, address, size)) in [
        (0u32, 0u8, 0u8, 0u16, 0u64, 0u64),
        (1, 0x02, 0, 1, 0x401100, 8),
        (8, 0x12, 0, 1, 0x401200, 24),
        (14, 0x11, 2, 1, 0x402000, 4),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x500 + index * 24;
        bytes[at..at + 4].copy_from_slice(&name.to_le_bytes());
        bytes[at + 4] = info;
        bytes[at + 5] = visibility;
        bytes[at + 6..at + 8].copy_from_slice(&section.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&address.to_le_bytes());
        bytes[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
    }
    bytes[0x580..0x595].copy_from_slice(b"\0helper\0entry\0hidden\0");
    bytes
}

fn elf32_be_static_symbol_fixture() -> Vec<u8> {
    let mut bytes = elf32_be_dynamic_symbol_fixture();
    bytes.resize(0x500, 0);
    bytes[32..36].copy_from_slice(&0x300u32.to_be_bytes());
    bytes[46..48].copy_from_slice(&40u16.to_be_bytes());
    bytes[48..50].copy_from_slice(&3u16.to_be_bytes());
    let symtab = 0x300 + 40;
    bytes[symtab + 4..symtab + 8].copy_from_slice(&2u32.to_be_bytes());
    bytes[symtab + 16..symtab + 20].copy_from_slice(&0x380u32.to_be_bytes());
    bytes[symtab + 20..symtab + 24].copy_from_slice(&48u32.to_be_bytes());
    bytes[symtab + 24..symtab + 28].copy_from_slice(&2u32.to_be_bytes());
    bytes[symtab + 36..symtab + 40].copy_from_slice(&16u32.to_be_bytes());
    let strtab = 0x300 + 80;
    bytes[strtab + 4..strtab + 8].copy_from_slice(&3u32.to_be_bytes());
    bytes[strtab + 16..strtab + 20].copy_from_slice(&0x400u32.to_be_bytes());
    bytes[strtab + 20..strtab + 24].copy_from_slice(&14u32.to_be_bytes());
    for (index, (name, address, size, info, section)) in [
        (0u32, 0u32, 0u32, 0u8, 0u16),
        (1, 0x2100, 4, 0x02, 1),
        (7, 0x2200, 8, 0x12, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 0x380 + index * 16;
        bytes[at..at + 4].copy_from_slice(&name.to_be_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&address.to_be_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&size.to_be_bytes());
        bytes[at + 12] = info;
        bytes[at + 14..at + 16].copy_from_slice(&section.to_be_bytes());
    }
    bytes[0x400..0x40e].copy_from_slice(b"\0local\0global\0");
    bytes
}

#[test]
fn native_elf_static_symbols_match_vm_and_are_separate_from_dynamic_symbols() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let file = s.0.join("symbols.elf");
    let script = s.write(
        "static_symbols.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, symbol_count, static_symbol_count, static_symbol_name, static_symbol_binding, static_symbol_type, static_symbol_visibility, static_symbol_role, static_symbol_address, static_symbol_size, static_symbol_section, static_symbol_defined, static_symbol_summary\nfrom std.iter import range\nlet report: Format = probe(analyze(\"symbols.elf\", 4096))\nprint symbol_count(report)\nprint static_symbol_count(report)\nfor index in range(static_symbol_count(report)) {\n    print static_symbol_name(report, index)\n    print static_symbol_binding(report, index)\n    print static_symbol_type(report, index)\n    print static_symbol_visibility(report, index)\n    print static_symbol_role(report, index)\n    print static_symbol_address(report, index)\n    print static_symbol_size(report, index)\n    print static_symbol_section(report, index)\n    print static_symbol_defined(report, index)\n    print static_symbol_summary(report, index)\n}\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let mut bytes = elf_static_symbol_fixture();
    fs::write(&file, &bytes).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(b"3\n4\n"));
    assert!(String::from_utf8_lossy(&native.stdout).contains("helper [local function] @ 0x401100"));
    assert!(
        String::from_utf8_lossy(&native.stdout).contains("entry [exported function] @ 0x401200")
    );
    assert!(String::from_utf8_lossy(&native.stdout).contains("hidden [local object] @ 0x402000"));

    bytes[0x380 + 3 * 64 + 40..0x380 + 3 * 64 + 44].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&file, &bytes).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("linked SHT_STRTAB"));
    assert!(String::from_utf8_lossy(&native.stderr).contains("linked SHT_STRTAB"));

    fs::write(&file, elf_dynamic_symbol_fixture(true, false)).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(vm.status.success());
    assert!(native.status.success());
    assert_eq!(vm.stdout, b"3\n0\n");
    assert_eq!(native.stdout, vm.stdout);

    fs::write(&file, elf32_be_static_symbol_fixture()).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(vm.stdout, native.stdout);
    assert!(vm.stdout.starts_with(b"3\n3\n"));
    assert!(String::from_utf8_lossy(&native.stdout).contains("global [exported function] @ 0x2200"));
}

#[test]
fn native_elf_dynamic_symbols_match_vm_for_sections_and_hash_tables() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let file = s.0.join("symbols.elf");
    let script = s.write(
        "symbols.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, symbol_count, symbol_name, symbol_binding, symbol_type, symbol_visibility, symbol_role, symbol_address, symbol_size, symbol_section, symbol_defined, symbol_summary\nfrom std.iter import range\nlet report: Format = probe(analyze(\"symbols.elf\", 4096))\nprint symbol_count(report)\nfor index in range(symbol_count(report)) {\n    print symbol_name(report, index)\n    print symbol_binding(report, index)\n    print symbol_type(report, index)\n    print symbol_visibility(report, index)\n    print symbol_role(report, index)\n    print symbol_address(report, index)\n    print symbol_size(report, index)\n    print symbol_section(report, index)\n    print symbol_defined(report, index)\n    print symbol_summary(report, index)\n}\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    for (sections, gnu_hash) in [(true, false), (false, false), (false, true)] {
        let mut bytes = elf_dynamic_symbol_fixture(sections, gnu_hash);
        fs::write(&file, &bytes).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(
            vm.status.success(),
            "{}",
            String::from_utf8_lossy(&vm.stderr)
        );
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout);
        assert!(native
            .stdout
            .starts_with(b"3\n\nlocal\nnotype\ndefault\nundefined\n"));
        assert!(native
            .stdout
            .ends_with(b"inspect [exported function] @ 0x401000\n"));

        bytes[0x200 + 2 * 24..0x204 + 2 * 24].copy_from_slice(&20u32.to_le_bytes());
        fs::write(&file, &bytes).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(!vm.status.success());
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&vm.stderr)
            .contains("ELF dynamic symbol name offset out of range"));
        assert!(String::from_utf8_lossy(&native.stderr)
            .contains("ELF dynamic symbol name offset out of range"));
    }

    fs::write(&file, elf32_be_dynamic_symbol_fixture()).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native
        .stdout
        .ends_with(b"inspect [exported function] @ 0x2000\n"));

    let mut oversized = elf_dynamic_symbol_fixture(true, false);
    oversized[0x200 + 2 * 24 + 16..0x200 + 2 * 24 + 24]
        .copy_from_slice(&(i64::MAX as u64 + 1).to_le_bytes());
    fs::write(&file, oversized).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("dynamic symbol size outside i64 range"));
    assert!(
        String::from_utf8_lossy(&native.stderr).contains("dynamic symbol size outside i64 range")
    );
}

#[test]
fn native_pe_relocations_match_vm_and_reject_malformed_blocks() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let optional = 0x98;
    let section = optional + 0xf0;
    let mut bytes = vec![0u8; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&6u32.to_le_bytes());
    bytes[optional + 152..optional + 156].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 156..optional + 160].copy_from_slice(&12u32.to_le_bytes());
    bytes[section..section + 6].copy_from_slice(b".reloc");
    bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[0x204..0x208].copy_from_slice(&12u32.to_le_bytes());
    bytes[0x208..0x20a].copy_from_slice(&0xa020u16.to_le_bytes());
    let file = s.0.join("relocations.pe");
    fs::write(&file, &bytes).unwrap();
    let script = s.write(
        "relocations.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, relocation_count, relocation_location, relocation_rva, relocation_address, relocation_type, relocation_kind, relocation_summary, relocation_symbol, relocation_addend\nfrom std.iter import range\nfrom std.result import is_error, message\nlet report: Format = probe(analyze(\"relocations.pe\", 4096))\nfn missing_symbol() -> Result<i64> = relocation_symbol(report, 0)\nfn missing_addend() -> Result<i64> = relocation_addend(report, 0)\nprint relocation_count(report)\nprint relocation_location(report)\nfor index in range(relocation_count(report)) {\n    print relocation_summary(report, index)\n    print relocation_rva(report, index)\n    print relocation_address(report, index)\n    print relocation_type(report, index)\n    print relocation_kind(report, index)\n}\nprint is_error(missing_symbol())\nprint message(missing_symbol())\nprint is_error(missing_addend())\nprint message(missing_addend())\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"1\nrva\nDIR64 @ 0x1020\n4128\n0x1020\n10\nDIR64\ntrue\nELF relocation expected\ntrue\nrelocation has no explicit addend\n");

    for (offset, replacement, error) in [
        (
            0x204,
            7u32.to_le_bytes(),
            "invalid PE base relocation block size",
        ),
        (
            0x200,
            0xfffff001u32.to_le_bytes(),
            "PE base relocation RVA outside address space",
        ),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 4].copy_from_slice(&replacement);
        if offset == 0x200 {
            invalid[0x208..0x20a].copy_from_slice(&0xafffu16.to_le_bytes());
        }
        fs::write(&file, invalid).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(!vm.status.success());
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&vm.stderr).contains(error));
        assert!(String::from_utf8_lossy(&native.stderr).contains(error));
    }
}

#[test]
fn native_pe_debug_entries_match_vm_and_reject_malformed_directories() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut bytes = vec![0u8; 0x500];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x98 + 108..0x98 + 112].copy_from_slice(&7u32.to_le_bytes());
    bytes[0x98 + 160..0x98 + 164].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[0x98 + 164..0x98 + 168].copy_from_slice(&28u32.to_le_bytes());
    let section = 0x98 + 0xf0;
    bytes[section..section + 6].copy_from_slice(b".rdata");
    bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x204..0x208].copy_from_slice(&0x12345678u32.to_le_bytes());
    bytes[0x20c..0x210].copy_from_slice(&2u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&39u32.to_le_bytes());
    bytes[0x218..0x21c].copy_from_slice(&0x480u32.to_le_bytes());
    bytes[0x480..0x484].copy_from_slice(b"RSDS");
    bytes[0x484..0x494].copy_from_slice(&[
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    bytes[0x494..0x498].copy_from_slice(&2u32.to_le_bytes());
    bytes[0x498..0x4a7].copy_from_slice(b"build\\demo.pdb\0");
    let file = s.0.join("sample.pe");
    fs::write(&file, &bytes).unwrap();
    let script = s.write(
        "debug.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, debug_count, debug_size, debug_timestamp, debug_kind, debug_type, debug_pdb_path, debug_pdb_guid, debug_pdb_age\nlet report: Format = probe(analyze(\"sample.pe\", 4096))\nprint debug_count(report)\nprint debug_size(report, 0)\nprint debug_timestamp(report, 0)\nprint debug_kind(report, 0)\nprint debug_type(report, 0)\nprint debug_pdb_path(report, 0)\nprint debug_pdb_guid(report, 0)\nprint debug_pdb_age(report, 0)\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"1\n39\n305419896\n2\ncodeview\nbuild\\demo.pdb\n00112233-4455-6677-8899-aabbccddeeff\n2\n");

    let mut invalid = bytes;
    invalid[0x98 + 164..0x98 + 168].copy_from_slice(&27u32.to_le_bytes());
    fs::write(&file, invalid).unwrap();
    let vm = run_vm();
    let native = run_native();
    assert!(!vm.status.success());
    assert!(!native.status.success());
    assert!(String::from_utf8_lossy(&vm.stderr).contains("PE debug directory has a partial entry"));
    assert!(
        String::from_utf8_lossy(&native.stderr).contains("PE debug directory has a partial entry")
    );
}

#[test]
fn native_pe_certificates_match_vm_and_reject_malformed_tables() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut bytes = vec![0u8; 0x22c];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x98 + 108..0x98 + 112].copy_from_slice(&5u32.to_le_bytes());
    bytes[0x98 + 144..0x98 + 148].copy_from_slice(&0x208u32.to_le_bytes());
    bytes[0x98 + 148..0x98 + 152].copy_from_slice(&32u32.to_le_bytes());
    let section = 0x80 + 4 + 20 + 0xf0;
    bytes[section + 16..section + 20].copy_from_slice(&4u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(b"CODE");
    bytes[0x208..0x20c].copy_from_slice(&11u32.to_le_bytes());
    bytes[0x20c..0x20e].copy_from_slice(&0x200u16.to_le_bytes());
    bytes[0x20e..0x210].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x210..0x213].copy_from_slice(b"ABC");
    bytes[0x218..0x21c].copy_from_slice(&12u32.to_le_bytes());
    bytes[0x21c..0x21e].copy_from_slice(&0x100u16.to_le_bytes());
    bytes[0x21e..0x220].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x220..0x224].copy_from_slice(b"DATA");
    let file = s.0.join("sample.pe");
    fs::write(&file, &bytes).unwrap();
    let script = s.write(
        "certificates.gak",
        "requires { file.read }\nfrom std.binary import analyze, extract, size\nfrom std.bytes import to_hex\nfrom std.formats import probe, certificate_count, certificate_data, certificate_offset, certificate_size, certificate_revision, certificate_type\nfrom std.iter import range\nlet report: Format = probe(analyze(\"sample.pe\", 4096))\nprint certificate_count(report)\nfor index in range(certificate_count(report)) {\n    let payload: Source = certificate_data(report, index)\n    print certificate_offset(report, index)\n    print certificate_size(report, index)\n    print certificate_revision(report, index)\n    print certificate_type(report, index)\n    print to_hex(extract(payload, 0, size(payload)))\n}\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        native.stdout,
        b"2\n528\n3\n512\n2\n414243\n544\n4\n256\n1\n44415441\n"
    );

    for (offset, replacement, error) in [
        (
            0x98 + 144,
            0x209u32.to_le_bytes(),
            "PE certificate table is not 8-byte aligned",
        ),
        (
            0x98 + 144,
            0x200u32.to_le_bytes(),
            "PE certificate table overlaps headers or sections",
        ),
        (
            0x208,
            7u32.to_le_bytes(),
            "PE certificate entry is shorter than its header",
        ),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 4].copy_from_slice(&replacement);
        fs::write(&file, invalid).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(!vm.status.success());
        assert!(!native.status.success());
        assert!(String::from_utf8_lossy(&vm.stderr).contains(error));
        assert!(String::from_utf8_lossy(&native.stderr).contains(error));
    }
}

#[test]
fn native_pe_exports_match_vm_for_names_ordinals_and_forwarders() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let optional = 0x98;
    let section = optional + 0xf0;
    let mut bytes = vec![0u8; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&1u32.to_le_bytes());
    bytes[optional + 112..optional + 116].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 116..optional + 120].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[section..section + 6].copy_from_slice(b".edata");
    bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&5u32.to_le_bytes());
    bytes[0x214..0x218].copy_from_slice(&3u32.to_le_bytes());
    bytes[0x218..0x21c].copy_from_slice(&2u32.to_le_bytes());
    bytes[0x21c..0x220].copy_from_slice(&0x1040u32.to_le_bytes());
    bytes[0x220..0x224].copy_from_slice(&0x1060u32.to_le_bytes());
    bytes[0x224..0x228].copy_from_slice(&0x1070u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&0x1080u32.to_le_bytes());
    bytes[0x248..0x24c].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[0x260..0x264].copy_from_slice(&0x10a0u32.to_le_bytes());
    bytes[0x264..0x268].copy_from_slice(&0x10a8u32.to_le_bytes());
    bytes[0x272..0x274].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x280..0x28d].copy_from_slice(b"OTHER.Target\0");
    bytes[0x2a0..0x2a6].copy_from_slice(b"Alpha\0");
    bytes[0x2a8..0x2ad].copy_from_slice(b"Beta\0");
    let file = s.0.join("exports.pe");
    fs::write(&file, &bytes).unwrap();
    let script = s.write(
        "exports.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, export_count, export_name, export_ordinal, export_address, export_target, export_kind, export_summary\nfrom std.iter import range\nfrom std.result import is_error, message\nlet report: Format = probe(analyze(\"exports.pe\", 4096))\nfn forwarded() -> Result<i64> = export_address(report, 1)\nprint export_count(report)\nprint export_address(report, 0)\nfor index in range(export_count(report)) {\n    print export_summary(report, index)\n    print export_name(report, index)\n    print export_ordinal(report, index)\n    print export_target(report, index)\n    print export_kind(report, index)\n}\nprint is_error(forwarded())\nprint message(forwarded())\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let run_vm = || {
        Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let run_native = || {
        Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap()
    };
    let vm = run_vm();
    let native = run_native();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    let output = String::from_utf8_lossy(&vm.stdout);
    assert!(output.contains("Alpha (#5) @ 0x2000"));
    assert!(output.contains("Beta (#6) -> OTHER.Target"));
    assert!(output.contains("#7 @ 0x3000"));
    assert!(output.contains("forwarded export has no direct address"));

    for (label, offset, replacement, error) in [
        (
            "invalid ordinal index",
            0x270,
            3u16.to_le_bytes().to_vec(),
            "PE export name ordinal index out of range",
        ),
        (
            "named empty address",
            0x240,
            0u32.to_le_bytes().to_vec(),
            "PE export name points to an empty address",
        ),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + replacement.len()].copy_from_slice(&replacement);
        fs::write(&file, invalid).unwrap();
        let vm = run_vm();
        let native = run_native();
        assert!(!vm.status.success(), "{label}");
        assert!(!native.status.success(), "{label}");
        assert!(
            String::from_utf8_lossy(&vm.stderr).contains(error),
            "{label}"
        );
        assert!(
            String::from_utf8_lossy(&native.stderr).contains(error),
            "{label}"
        );
    }
}

#[test]
fn native_pe_and_elf_dependencies_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut pe = vec![0u8; 0x400];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    pe[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x98 + 92..0x98 + 96].copy_from_slice(&2u32.to_le_bytes());
    pe[0x98 + 104..0x98 + 108].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x98 + 108..0x98 + 112].copy_from_slice(&40u32.to_le_bytes());
    let section = 0x98 + 0xe0;
    pe[section..section + 6].copy_from_slice(b".idata");
    pe[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    pe[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    pe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x200..0x204].copy_from_slice(&0x1040u32.to_le_bytes());
    pe[0x20c..0x210].copy_from_slice(&0x1080u32.to_le_bytes());
    pe[0x210..0x214].copy_from_slice(&0x1060u32.to_le_bytes());
    pe[0x240..0x244].copy_from_slice(&0x10a0u32.to_le_bytes());
    pe[0x244..0x248].copy_from_slice(&(1u32 << 31 | 7).to_le_bytes());
    pe[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
    pe[0x2a2..0x2ae].copy_from_slice(b"CreateFileW\0");

    let mut elf = vec![0u8; 0x300];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[1, 1, 1]);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf[18..20].copy_from_slice(&3u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
    elf[28..32].copy_from_slice(&52u32.to_le_bytes());
    elf[40..42].copy_from_slice(&52u16.to_le_bytes());
    elf[42..44].copy_from_slice(&32u16.to_le_bytes());
    elf[44..46].copy_from_slice(&2u16.to_le_bytes());
    elf[52..56].copy_from_slice(&1u32.to_le_bytes());
    elf[60..64].copy_from_slice(&0x1000u32.to_le_bytes());
    elf[68..72].copy_from_slice(&0x300u32.to_le_bytes());
    elf[72..76].copy_from_slice(&0x300u32.to_le_bytes());
    elf[76..80].copy_from_slice(&5u32.to_le_bytes());
    elf[84..88].copy_from_slice(&2u32.to_le_bytes());
    elf[88..92].copy_from_slice(&0x100u32.to_le_bytes());
    elf[92..96].copy_from_slice(&0x1100u32.to_le_bytes());
    elf[100..104].copy_from_slice(&32u32.to_le_bytes());
    elf[104..108].copy_from_slice(&32u32.to_le_bytes());
    elf[0x100..0x108].copy_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0]);
    elf[0x108..0x110].copy_from_slice(&[5, 0, 0, 0, 0, 0x12, 0, 0]);
    elf[0x110..0x118].copy_from_slice(&[10, 0, 0, 0, 32, 0, 0, 0]);
    elf[0x200..0x20e].copy_from_slice(b"\0libsample.so\0");
    let mut delay = vec![0u8; 0x400];
    delay[..2].copy_from_slice(b"MZ");
    delay[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    delay[0x80..0x84].copy_from_slice(b"PE\0\0");
    delay[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    delay[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    delay[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    let optional = 0x98;
    delay[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    delay[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    delay[optional + 108..optional + 112].copy_from_slice(&14u32.to_le_bytes());
    delay[optional + 120..optional + 124].copy_from_slice(&0x1000u32.to_le_bytes());
    delay[optional + 124..optional + 128].copy_from_slice(&40u32.to_le_bytes());
    delay[optional + 216..optional + 220].copy_from_slice(&0x1100u32.to_le_bytes());
    delay[optional + 220..optional + 224].copy_from_slice(&64u32.to_le_bytes());
    let section = optional + 0xf0;
    delay[section..section + 6].copy_from_slice(b".idata");
    delay[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    delay[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    delay[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    delay[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    delay[0x200..0x204].copy_from_slice(&0x1040u32.to_le_bytes());
    delay[0x20c..0x210].copy_from_slice(&0x1080u32.to_le_bytes());
    delay[0x210..0x214].copy_from_slice(&0x1060u32.to_le_bytes());
    delay[0x240..0x248].copy_from_slice(&0x10a0u64.to_le_bytes());
    delay[0x248..0x250].copy_from_slice(&(1u64 << 63 | 7).to_le_bytes());
    delay[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
    delay[0x2a2..0x2ae].copy_from_slice(b"CreateFileW\0");
    delay[0x300..0x304].copy_from_slice(&1u32.to_le_bytes());
    delay[0x304..0x308].copy_from_slice(&0x1160u32.to_le_bytes());
    delay[0x30c..0x310].copy_from_slice(&0x1150u32.to_le_bytes());
    delay[0x310..0x314].copy_from_slice(&0x1140u32.to_le_bytes());
    delay[0x340..0x348].copy_from_slice(&0x1180u64.to_le_bytes());
    delay[0x348..0x350].copy_from_slice(&(1u64 << 63 | 9).to_le_bytes());
    delay[0x360..0x36b].copy_from_slice(b"USER32.dll\0");
    delay[0x382..0x38e].copy_from_slice(b"MessageBoxA\0");
    let mut delay_va = delay.clone();
    let image_base = 0x1000_0000u64;
    delay_va[optional + 24..optional + 32].copy_from_slice(&image_base.to_le_bytes());
    delay_va[0x300..0x304].fill(0);
    delay_va[0x304..0x308].copy_from_slice(&((image_base + 0x1160) as u32).to_le_bytes());
    delay_va[0x310..0x314].copy_from_slice(&((image_base + 0x1140) as u32).to_le_bytes());
    delay_va[0x340..0x348].copy_from_slice(&(image_base + 0x1180).to_le_bytes());
    fs::write(s.0.join("sample.pe"), &pe).unwrap();
    fs::write(s.0.join("sample.elf"), &elf).unwrap();
    fs::write(s.0.join("sample-delay.pe"), &delay).unwrap();
    fs::write(s.0.join("sample-delay-va.pe"), &delay_va).unwrap();
    let script = s.write(
        "dependencies.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, kind, dependency_count, dependency_name, needed_count, needed_name, import_count, import_library, import_symbol, import_kind, import_summary, delay_dependency_count, delay_dependency_name, delay_import_count, delay_import_library, delay_import_symbol, delay_import_kind, delay_import_summary\nfrom std.iter import range\nfrom std.cli import arg\nfrom std.result import is_error, message\nlet report: Format = probe(analyze(arg(0), 4096))\nfn missing() -> Result<str> = dependency_name(report, 1)\nprint kind(report)\nprint dependency_count(report)\nprint dependency_name(report, 0)\nif kind(report) == \"elf\" {\n    print needed_count(report)\n    print needed_name(report, 0)\n} else {\n    print import_count(report)\n    for index in range(import_count(report)) {\n        print import_summary(report, index)\n        print import_library(report, index)\n        print import_symbol(report, index)\n        print import_kind(report, index)\n    }\n    print delay_dependency_count(report)\n    for index in range(delay_dependency_count(report)) {\n        print delay_dependency_name(report, index)\n    }\n    print delay_import_count(report)\n    for index in range(delay_import_count(report)) {\n        print delay_import_summary(report, index)\n        print delay_import_library(report, index)\n        print delay_import_symbol(report, index)\n        print delay_import_kind(report, index)\n    }\n}\nprint is_error(missing())\nprint message(missing())\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    for fixture in [
        "sample.pe",
        "sample.elf",
        "sample-delay.pe",
        "sample-delay-va.pe",
    ] {
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .args(["--", fixture])
            .output()
            .unwrap();
        assert!(
            vm.status.success(),
            "{fixture}: {}",
            String::from_utf8_lossy(&vm.stderr)
        );
        let native = Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .args(["--", fixture])
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{fixture}: {}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout, "{fixture}");
        if fixture == "sample.pe" {
            assert!(String::from_utf8_lossy(&vm.stdout).contains("KERNEL32.dll!CreateFileW"));
            assert!(String::from_utf8_lossy(&vm.stdout).contains("KERNEL32.dll!#7"));
        }
        if fixture.starts_with("sample-delay") {
            assert!(String::from_utf8_lossy(&vm.stdout).contains("USER32.dll!MessageBoxA"));
            assert!(String::from_utf8_lossy(&vm.stdout).contains("USER32.dll!#9"));
        }
    }

    let mut invalid_ordinal = pe.clone();
    invalid_ordinal[0x244..0x248].copy_from_slice(&(1u32 << 31 | 1u32 << 16 | 7).to_le_bytes());
    let mut invalid_delay = delay.clone();
    invalid_delay[0x300..0x304].copy_from_slice(&2u32.to_le_bytes());
    let mut invalid_delay_va = delay_va.clone();
    invalid_delay_va[0x304..0x308].copy_from_slice(&0x1160u32.to_le_bytes());
    pe[0x98 + 108..0x98 + 112].copy_from_slice(&20u32.to_le_bytes());
    elf[100..104].copy_from_slice(&40u32.to_le_bytes());
    elf[104..108].copy_from_slice(&40u32.to_le_bytes());
    elf[0x118..0x120].copy_from_slice(&[5, 0, 0, 0, 0, 0x12, 0, 0]);
    for (fixture, bytes, error) in [
        (
            "invalid.pe",
            pe,
            "PE import directory has no null descriptor",
        ),
        ("invalid.elf", elf, "duplicate ELF DT_STRTAB"),
        (
            "invalid-ordinal.pe",
            invalid_ordinal,
            "PE import ordinal has reserved bits set",
        ),
        (
            "invalid-delay.pe",
            invalid_delay,
            "PE delay import descriptor has reserved attribute bits",
        ),
        (
            "invalid-delay-va.pe",
            invalid_delay_va,
            "PE delay import VA is below image base",
        ),
    ] {
        fs::write(s.0.join(fixture), bytes).unwrap();
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .args(["--", fixture])
            .output()
            .unwrap();
        let native = Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .args(["--", fixture])
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{fixture}");
        assert!(!native.status.success(), "{fixture}");
        assert!(
            String::from_utf8_lossy(&vm.stderr).contains(error),
            "{fixture}"
        );
        assert!(
            String::from_utf8_lossy(&native.stderr).contains(error),
            "{fixture}"
        );
    }
}

#[test]
fn native_format_address_mapping_boundaries_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut pe = vec![0u8; 0x120];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x014cu16.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    pe[0x54..0x56].copy_from_slice(&0x60u16.to_le_bytes());
    pe[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
    pe[0x68..0x6c].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x94..0x98].copy_from_slice(&0x100u32.to_le_bytes());
    pe[0xc0..0xc4].copy_from_slice(&0x20u32.to_le_bytes());
    pe[0xc4..0xc8].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xc8..0xcc].copy_from_slice(&0x10u32.to_le_bytes());
    pe[0xcc..0xd0].copy_from_slice(&0x100u32.to_le_bytes());
    pe[0x100..0x110].copy_from_slice(b"0123456789abcdef");
    pe[0x110..0x120].copy_from_slice(b"PE-OVERLAY-TEST!");

    let mut elf = vec![0u8; 0x120];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[1, 1, 1]);
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&3u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
    elf[28..32].copy_from_slice(&52u32.to_le_bytes());
    elf[40..42].copy_from_slice(&52u16.to_le_bytes());
    elf[42..44].copy_from_slice(&32u16.to_le_bytes());
    elf[44..46].copy_from_slice(&1u16.to_le_bytes());
    elf[52..56].copy_from_slice(&1u32.to_le_bytes());
    elf[56..60].copy_from_slice(&0x100u32.to_le_bytes());
    elf[60..64].copy_from_slice(&0x1000u32.to_le_bytes());
    elf[68..72].copy_from_slice(&0x10u32.to_le_bytes());
    elf[72..76].copy_from_slice(&0x20u32.to_le_bytes());
    elf[76..80].copy_from_slice(&5u32.to_le_bytes());
    elf[0x100..0x110].copy_from_slice(b"0123456789abcdef");
    elf[0x110..0x120].copy_from_slice(b"ELF-OVERLAY-TST!");

    for (label, bytes, mapper, missing) in [("pe", pe, "rva", 0x2000), ("elf", elf, "va", 0x2000)] {
        let file = s.0.join(format!("{label}.bin"));
        fs::write(&file, bytes).unwrap();
        let script = s.write(
            &format!("{label}-mapping.gak"),
            &format!("requires {{ file.read }}\nfrom std.binary import analyze, sha256, size\nfrom std.formats import probe, overlay, entry_view, rva, va\nfrom std.result import is_error\nlet report: Format = probe(analyze(\"{label}.bin\", 1024))\nfn header() -> Result<Source> = {mapper}(report, 0, 4)\nfn virtual_only() -> Result<Source> = {mapper}(report, 0x1010, 1)\nfn crossing() -> Result<Source> = {mapper}(report, 0x100f, 2)\nfn missing() -> Result<Source> = {mapper}(report, {missing}, 1)\nfn empty() -> Result<Source> = {mapper}(report, 0x1000, 0)\nprint entry_view(report, 8)\nprint sha256({mapper}(report, 0x1000, 16))\nprint size(overlay(report))\nprint is_error(header())\nprint is_error(virtual_only())\nprint is_error(crossing())\nprint is_error(missing())\nprint is_error(empty())\n"),
        );
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .output()
            .unwrap();
        assert!(
            vm.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&vm.stderr)
        );
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert_eq!(native.stdout, vm.stdout, "{label}");
    }
}

#[test]
fn native_format_address_views_match_vm_for_pe_and_elf() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let (mapped, wrong) = if cfg!(windows) {
        ("rva", "va")
    } else {
        ("va", "rva")
    };
    let source = format!(
        "requires {{ file.read }}\nfrom std.binary import analyze, sha256, size, value, view\nfrom std.formats import probe, field, overlay, entry_view, rva, va\nfrom std.result import is_error\nfrom std.cli import arg\nlet report: Format = probe(analyze(arg(0), 67108864))\nlet entry: Source = entry_view(report, 8)\nlet mapped: Source = {mapped}(report, value(field(report, \"entry\")), 8)\nlet trailing: Source = overlay(report)\nfn wrong_format() -> Result<Source> = {wrong}(report, 0, 1)\nfn missing_address() -> Result<Source> = {mapped}(report, 9223372036854775807, 1)\nfn empty_entry() -> Result<Source> = entry_view(report, 0)\nprint entry\nprint mapped\nprint view(mapped, 1, 2)\nprint sha256(entry)\nprint size(trailing)\nprint trailing\nprint is_error(wrong_format())\nprint is_error(missing_address())\nprint is_error(empty_entry())\n"
    );
    let script = s.write("address-views.gak", &source);
    let input = if cfg!(windows) {
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32/notepad.exe")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    let root = input.parent().unwrap();
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .arg("--allow-read")
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_format_sections_match_vm_and_keep_data_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let data_index = if cfg!(windows) { 0 } else { 1 };
    let script = s.write(
        "format-sections.gak",
        &format!("requires {{ file.read }}\nfrom std.binary import analyze, sha256, size as binary_size\nfrom std.formats import probe, section, name, offset, size, virtual_size, address, flags, writable, executable, data\nfrom std.result import is_error\nfrom std.cli import arg\nlet report: Format = probe(analyze(arg(0), 67108864))\nlet first: Section = section(report, 0)\nlet chosen: Section = section(report, {data_index})\nfn invalid_section() -> Result<Section> = section(report, 999999)\nprint name(first)\nprint offset(first)\nprint size(first)\nprint virtual_size(first)\nprint address(first)\nprint flags(first)\nprint writable(first)\nprint executable(first)\nprint is_error(invalid_section())\nprint name(chosen)\nprint binary_size(data(chosen))\nprint sha256(data(chosen))\n"),
    );
    let input = if cfg!(windows) {
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32/notepad.exe")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    let root = input.parent().unwrap();
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .arg("--allow-read")
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_format_profile_matches_vm_for_executable_and_rejects_bad_header() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut source = String::from(
        "requires { file.read }\nfrom std.binary import analyze, value, offset, width\nfrom std.formats import probe, kind, bits, endian, arch, count, signal, field\nfrom std.result import is_error\nfrom std.cli import arg\nlet report: Format = probe(analyze(arg(0), 67108864))\nfn invalid_signal() -> Result<str> = signal(report, \"invalid.signal\")\nfn invalid_field() -> Result<Observation> = field(report, \"invalid.field\")\nprint kind(report)\nprint bits(report)\nprint endian(report)\nprint arch(report)\nprint count(report)\nprint value(field(report, \"machine\"))\nprint offset(field(report, \"entry\"))\nprint width(field(report, \"entry\"))\nprint value(field(report, \"sections\"))\n",
    );
    for signal in [
        "pe.high_entropy_va",
        "pe.dynamic_base",
        "pe.nx_compat",
        "pe.guard_cf",
        "pe.section_wx",
        "elf.et_dyn",
        "elf.gnu_stack_nx",
        "elf.gnu_relro",
        "elf.bind_now",
        "elf.relro_now",
        "elf.load_rwx",
    ] {
        source.push_str(&format!("print signal(report, \"{signal}\")\n"));
    }
    source.push_str("print is_error(invalid_signal())\nprint is_error(invalid_field())\n");
    let script = s.write("format-profile.gak", &source);
    let input = if cfg!(windows) {
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32/notepad.exe")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    let root = input.parent().unwrap();
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .arg("--allow-read")
        .arg(root)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(if cfg!(windows) {
        b"pe\n64\nlittle\nx86_64\n"
    } else {
        b"elf\n64\nlittle\nx86_64\n"
    }));

    let damaged = s.0.join("damaged.bin");
    fs::write(&damaged, b"MZ").unwrap();
    for engine in ["vm", "native"] {
        let output = if engine == "vm" {
            Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("run")
                .arg(&script)
                .args(["--engine", "vm", "--allow-read"])
                .arg(&s.0)
                .arg("--")
                .arg(&damaged)
                .output()
                .unwrap()
        } else {
            Command::new(&executable)
                .arg("--allow-read")
                .arg(&s.0)
                .arg("--")
                .arg(&damaged)
                .output()
                .unwrap()
        };
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("truncated binary header"),
            "{engine}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let original = fs::read(&input).unwrap();
    let mut mutations = vec![
        ("empty", Vec::new()),
        ("prefix-2", original[..2].to_vec()),
        ("prefix-16", original[..16].to_vec()),
        ("prefix-64", original[..64].to_vec()),
    ];
    let mut invalid_magic = original.clone();
    invalid_magic[0] = 0;
    mutations.push(("magic", invalid_magic));
    if cfg!(windows) {
        let mut bad_pe_offset = original.clone();
        bad_pe_offset[0x3c..0x40].copy_from_slice(&0u32.to_le_bytes());
        mutations.push(("pe-offset", bad_pe_offset));
        let pe_offset = u32::from_le_bytes(original[0x3c..0x40].try_into().unwrap()) as usize;
        let mut bad_optional_magic = original.clone();
        bad_optional_magic[pe_offset + 24..pe_offset + 26].copy_from_slice(&0u16.to_le_bytes());
        mutations.push(("pe-optional-magic", bad_optional_magic));
        let mut bad_sections = original.clone();
        bad_sections[pe_offset + 6..pe_offset + 8].copy_from_slice(&u16::MAX.to_le_bytes());
        mutations.push(("pe-section-table", bad_sections));
    } else {
        let mut bad_class = original.clone();
        bad_class[4] = 0;
        mutations.push(("elf-class", bad_class));
        let mut bad_order = original.clone();
        bad_order[5] = 0;
        mutations.push(("elf-order", bad_order));
        let mut bad_version = original.clone();
        bad_version[6] = 0;
        mutations.push(("elf-version", bad_version));
        let mut bad_header_size = original.clone();
        bad_header_size[52..54].copy_from_slice(&0u16.to_le_bytes());
        mutations.push(("elf-header-size", bad_header_size));
        let mut bad_section_size = original.clone();
        bad_section_size[58..60].copy_from_slice(&0u16.to_le_bytes());
        mutations.push(("elf-section-size", bad_section_size));
        let shoff = u64::from_le_bytes(original[40..48].try_into().unwrap()) as usize;
        let shentsize = u16::from_le_bytes(original[58..60].try_into().unwrap()) as usize;
        let section = shoff + shentsize;
        let mut overflowing_section = original.clone();
        overflowing_section[section + 4..section + 8].copy_from_slice(&1u32.to_le_bytes());
        overflowing_section[section + 24..section + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        overflowing_section[section + 32..section + 40].copy_from_slice(&2u64.to_le_bytes());
        mutations.push(("elf-section-overflow", overflowing_section));
    }
    for (name, bytes) in mutations {
        let path = s.0.join(format!("{name}.bin"));
        fs::write(&path, bytes).unwrap();
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .arg("--")
            .arg(&path)
            .output()
            .unwrap();
        let native = Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .arg("--")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{name} should be rejected by VM");
        assert!(
            !native.status.success(),
            "{name} accepted natively: {}",
            String::from_utf8_lossy(&native.stdout)
        );
    }

    let mut elf32 = vec![0u8; 52];
    elf32[..4].copy_from_slice(b"\x7fELF");
    elf32[4..7].copy_from_slice(&[1, 1, 1]);
    elf32[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf32[18..20].copy_from_slice(&3u16.to_le_bytes());
    elf32[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf32[40..42].copy_from_slice(&52u16.to_le_bytes());
    let mut elf64_big = vec![0u8; 64];
    elf64_big[..4].copy_from_slice(b"\x7fELF");
    elf64_big[4..7].copy_from_slice(&[2, 2, 1]);
    elf64_big[16..18].copy_from_slice(&2u16.to_be_bytes());
    elf64_big[18..20].copy_from_slice(&183u16.to_be_bytes());
    elf64_big[20..24].copy_from_slice(&1u32.to_be_bytes());
    elf64_big[52..54].copy_from_slice(&64u16.to_be_bytes());
    let mut pe32 = vec![0u8; 108];
    pe32[..2].copy_from_slice(b"MZ");
    pe32[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    pe32[64..68].copy_from_slice(b"PE\0\0");
    pe32[68..70].copy_from_slice(&0x014cu16.to_le_bytes());
    pe32[84..86].copy_from_slice(&20u16.to_le_bytes());
    pe32[88..90].copy_from_slice(&0x10bu16.to_le_bytes());
    let mut pe64 = pe32.clone();
    pe64[68..70].copy_from_slice(&0xaa64u16.to_le_bytes());
    pe64[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    for (name, bytes, prefix) in [
        ("elf32", elf32, b"elf\n32\nlittle\nx86\n0\n".as_slice()),
        ("elf64-big", elf64_big, b"elf\n64\nbig\naarch64\n0\n"),
        ("pe32", pe32, b"pe\n32\nlittle\nx86\n0\n"),
        ("pe64", pe64, b"pe\n64\nlittle\naarch64\n0\n"),
    ] {
        let path = s.0.join(format!("{name}.bin"));
        fs::write(&path, bytes).unwrap();
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm", "--allow-read"])
            .arg(&s.0)
            .arg("--")
            .arg(&path)
            .output()
            .unwrap();
        let native = Command::new(&executable)
            .arg("--allow-read")
            .arg(&s.0)
            .arg("--")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            vm.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&vm.stderr)
        );
        assert!(
            native.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(vm.stdout.starts_with(prefix), "{name}: {:?}", vm.stdout);
        assert_eq!(native.stdout, vm.stdout, "{name}");
    }
}

#[test]
fn native_bytes_hex_and_index_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "bytes.gak",
        "from std.bytes import from_hex, to_hex, at\nfrom std.result import ok\nlet data: bytes = from_hex(\"00 Ff\\n41\")\nprint data\nprint to_hex(data)\nprint at(data, 0)\nprint at(data, 1)\nprint [data]\nprint ok(data)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        native.stdout,
        b"bytes(3 bytes, hex:00ff41)\n00ff41\n0\n255\n[bytes(3 bytes, hex:00ff41)]\nok(bytes(3 bytes, hex:00ff41))\n"
    );
}

#[test]
fn native_bytes_errors_match_vm_with_source_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("invalid-hex.gak", "from_hex(\"0x\")"),
        ("odd-hex.gak", "from_hex(\"f\")"),
        ("negative-index.gak", "at(from_hex(\"00\"), -1)"),
        ("long-index.gak", "at(from_hex(\"00\"), 1)"),
    ] {
        let source = format!("from std.bytes import from_hex, at\nprint {expression}\n");
        let script = s.write(name, &source);
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_bytes_transforms_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "bytes-transforms.gak",
        "from std.bytes import from_hex, to_hex, concat, repeat, xor, at\nlet left = from_hex(\"00 ff\")\nlet right = from_hex(\"41 42 43\")\nprint to_hex(concat(left, right))\nprint to_hex(repeat(right, 3))\nprint to_hex(repeat(left, 0))\nprint to_hex(repeat(from_hex(\"\"), 1048576))\nprint to_hex(xor(right, from_hex(\"ff 0f\")))\nprint to_hex(xor(left, from_hex(\"01\")))\nprint at(repeat(from_hex(\"7f\"), 1048576), 1048575)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        native.stdout,
        b"00ff414243\n414243414243414243\n\n\nbe4dbc\n01fe\n127\n"
    );
}

#[test]
fn native_bytes_transform_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("repeat-negative.gak", "repeat(from_hex(\"00\"), -1)"),
        ("repeat-count.gak", "repeat(from_hex(\"\"), 1048577)"),
        ("repeat-size.gak", "repeat(from_hex(\"00 01\"), 524289)"),
        ("xor-empty.gak", "xor(from_hex(\"00\"), from_hex(\"\"))"),
    ] {
        let source = format!("from std.bytes import from_hex, repeat, xor\nprint {expression}\n");
        let script = s.write(name, &source);
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_bytes_pack_matches_vm_across_widths_and_endianness() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "bytes-pack.gak",
        "from std.bytes import pack, to_hex\nprint to_hex(pack(0xab, \"u8\"))\nprint to_hex(pack(0x1234, \"u16le\"))\nprint to_hex(pack(0x1234, \"u16be\"))\nprint to_hex(pack(0x12345678, \"u32le\"))\nprint to_hex(pack(0x12345678, \"u32be\"))\nprint to_hex(pack(0x123456789abcdefu64, \"u64le\"))\nprint to_hex(pack(0x123456789abcdefu64, \"u64be\"))\nprint to_hex(pack(18446744073709551615u64, \"u64be\"))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"ab\n3412\n1234\n78563412\n12345678\nefcdab8967452301\n0123456789abcdef\nffffffffffffffff\n");
}

#[test]
fn native_bytes_pack_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("pack-negative.gak", "pack(-1, \"u8\")"),
        ("pack-u8-range.gak", "pack(256, \"u8\")"),
        ("pack-u16-range.gak", "pack(65536, \"u16be\")"),
        ("pack-u32-range.gak", "pack(4294967296u64, \"u32le\")"),
        ("pack-encoding.gak", "pack(1, \"u128le\")"),
    ] {
        let script = s.write(
            name,
            &format!("from std.bytes import pack\nprint {expression}\n"),
        );
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_binary_bytes_views_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-bytes.gak",
        "from std.binary import from_hex, size, extract\nlet data = from_hex(\"00 ff 01 02\")\nprint size(data)\nprint extract(data, 1, 2)\nprint size(extract(data, 4, 0))\nprint extract(data, 0, 4)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        native.stdout,
        b"4\nbytes(2 bytes, hex:ff01)\n0\nbytes(4 bytes, hex:00ff0102)\n"
    );
}

#[test]
fn native_binary_bytes_view_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("extract-offset.gak", "extract(from_hex(\"00\"), -1, 1)"),
        ("extract-length.gak", "extract(from_hex(\"00\"), 0, -1)"),
        ("extract-bound.gak", "extract(from_hex(\"00\"), 1, 1)"),
        (
            "extract-evaluation.gak",
            "extract(from_hex(\"00\"), -1, 1 / 0)",
        ),
    ] {
        let script = s.write(
            name,
            &format!("from std.binary import from_hex, extract\nprint {expression}\n"),
        );
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_sources_keep_nested_view_bounds_across_functions() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-sources.gak",
        "from std.binary import from_hex, snapshot, view, size, extract\nfrom std.bytes import to_hex\nfn inner(source: Source) -> Source = view(source, 1, 2)\nlet root: Source = snapshot(from_hex(\"00 11 22 33 44\"))\nlet first: Source = view(root, 1, 4)\nlet second: Source = inner(first)\nprint size(root)\nprint size(first)\nprint size(second)\nprint to_hex(extract(second, 0, 2))\nprint to_hex(extract(first, 2, 2))\nprint size(view(second, 2, 0))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(native.stdout, b"5\n4\n2\n2233\n3344\n0\n");
}

#[test]
fn native_source_view_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, body) in [
        ("source-offset.gak", "print size(view(snapshot(from_hex(\"00\")), -1, 1))"),
        ("source-bound.gak", "print size(view(snapshot(from_hex(\"00\")), 1, 1))"),
        ("source-depth.gak", "var current: Source = snapshot(from_hex(\"00\"))\nvar i = 0\nwhile i < 65 {\n    current = view(current, 0, 1)\n    i = i + 1\n}\nprint size(current)"),
    ] {
        let script = s.write(
            name,
            &format!("from std.binary import from_hex, snapshot, view, size\n{body}\n"),
        );
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success());
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success());
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_sha256_matches_vm_for_bytes_and_source_views() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-sha256.gak",
        "from std.binary import from_hex, snapshot, view, sha256\nfrom std.bytes import repeat\nprint sha256(from_hex(\"\"))\nprint sha256(from_hex(\"61 62 63\"))\nprint sha256(view(snapshot(from_hex(\"00 61 62 63 ff\")), 1, 3))\nprint sha256(repeat(from_hex(\"61\"), 55))\nprint sha256(repeat(from_hex(\"61\"), 56))\nprint sha256(repeat(from_hex(\"61\"), 64))\nprint sha256(repeat(from_hex(\"61\"), 65))\nprint sha256(repeat(from_hex(\"61\"), 1048576))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"));
}

#[test]
fn native_binary_deep_matches_vm_for_decoders_and_observations() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-deep.gak",
        "from std.binary import from_hex, snapshot, view, deep, value, value_u64, offset, width\nfrom std.result import ok\nstruct Reading { item: Observation }\nfn read(source: Source, at: i64, decoder: str) -> Observation = deep(source, at, decoder)\nlet root = snapshot(from_hex(\"01 02 03 04 05 06 07 08 ff ff ff ff ff ff ff ff\"))\nlet part = view(root, 1, 8)\nlet item: Observation = read(part, 2, \"u16be\")\nprint read(root, 0, \"u8\")\nprint read(part, 0, \"u16le\")\nprint read(part, 0, \"u16be\")\nprint value(read(root, 0, \"u32le\"))\nprint value(read(root, 0, \"u32be\"))\nprint value_u64(read(root, 0, \"u64le\"))\nprint value_u64(read(root, 0, \"u64be\"))\nprint value_u64(read(root, 8, \"u64be\"))\nprint offset(item)\nprint width(item)\nprint [item]\nprint ok(item)\nprint Reading(item)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_deep_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("deep-negative.gak", "deep(root, -1, \"u8\")"),
        ("deep-decoder.gak", "deep(root, 0, \"i32le\")"),
        ("deep-bounds.gak", "deep(root, 1, \"u16le\")"),
        ("deep-large.gak", "deep(root, 9223372036854775807, \"u8\")"),
        (
            "deep-value-range.gak",
            "value(deep(snapshot(from_hex(\"ff ff ff ff ff ff ff ff\")), 0, \"u64be\"))",
        ),
    ] {
        let script = s.write(name, &format!("from std.binary import from_hex, snapshot, deep, value\nlet root = snapshot(from_hex(\"ff\"))\nprint {expression}\n"));
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{name}");
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success(), "{name}");
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_binary_deep_errors_can_be_captured_as_result() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-deep-result.gak",
        "from std.binary import from_hex, snapshot, deep, value\nfrom std.result import is_error, message\nfn read(source: Source, decoder: str) -> Result<Observation> = deep(source, 0, decoder)\nfn narrow(source: Source) -> Result<i64> = value(deep(source, 0, \"u64be\"))\nlet tiny = snapshot(from_hex(\"ff\"))\nlet wide = snapshot(from_hex(\"ff ff ff ff ff ff ff ff\"))\nprint is_error(read(tiny, \"u32le\"))\nprint message(read(tiny, \"u32le\"))\nprint is_error(read(wide, \"invalid\"))\nprint message(read(wide, \"invalid\"))\nprint is_error(narrow(wide))\nprint message(narrow(wide))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_hexdump_matches_vm_at_row_and_length_boundaries() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-hexdump.gak",
        "from std.binary import from_hex, snapshot, view, hexdump\nfrom std.bytes import repeat\nlet empty = snapshot(from_hex(\"\"))\nlet root = snapshot(from_hex(\"00 1f 20 41 7e 7f 80 ff 01 02 03 04 05 06 07 08 09\"))\nlet part = view(root, 2, 15)\nlet large = snapshot(repeat(from_hex(\"41\"), 4097))\nprint hexdump(empty)\nprint hexdump(root)\nprint hexdump(part)\nprint hexdump(part, 1, 0)\nprint hexdump(part, 1, 1)\nprint hexdump(part, 1, 7)\nprint hexdump(part, 0, 8)\nprint hexdump(part, 0, 15)\nprint hexdump(root, 0, 16)\nprint hexdump(root, 0, 17)\nprint hexdump(large)\nprint hexdump(large, 1, 4096)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_hexdump_errors_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("hexdump-negative-offset.gak", "hexdump(source, -1, 1)"),
        ("hexdump-negative-length.gak", "hexdump(source, 0, -1)"),
        ("hexdump-out-of-bounds.gak", "hexdump(source, 4097, 1)"),
        ("hexdump-limit.gak", "hexdump(source, 0, 4097)"),
        ("hexdump-bound-first.gak", "hexdump(source, 1, 4097)"),
    ] {
        let script = s.write(name, &format!("from std.binary import from_hex, snapshot, hexdump\nfrom std.bytes import repeat\nlet source = snapshot(repeat(from_hex(\"41\"), 4097))\nprint {expression}\n"));
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{name}");
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success(), "{name}");
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
}

#[test]
fn native_binary_read_text_matches_vm_for_ascii_utf16le_and_views() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-read-text.gak",
        "from std.binary import from_hex, snapshot, view, read_text\nfrom std.bytes import repeat\nlet source = snapshot(from_hex(\"00 47 41 4b 00 61 62 63 20 31 ff 58 00 59 00 00\"))\nlet part = view(source, 5, 5)\nlet large = snapshot(repeat(from_hex(\"41\"), 4096))\nprint read_text(source, 1, 3, \"ascii\")\nprint read_text(source, 5, 5, \"ascii\")\nprint read_text(source, 11, 2, \"utf16le\")\nprint read_text(part, 0, 5, \"ascii\")\nprint read_text(large, 0, 4096, \"ascii\")\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_read_text_errors_match_vm_and_result_capture() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        (
            "text-negative-offset.gak",
            "read_text(source, -1, 1, \"ascii\")",
        ),
        (
            "text-negative-max.gak",
            "read_text(source, 0, -1, \"ascii\")",
        ),
        ("text-zero-max.gak", "read_text(source, 0, 0, \"ascii\")"),
        (
            "text-large-max.gak",
            "read_text(source, 0, 4097, \"ascii\")",
        ),
        ("text-encoding.gak", "read_text(source, 0, 1, \"utf8\")"),
        (
            "text-out-of-bounds.gak",
            "read_text(source, 4097, 1, \"ascii\")",
        ),
        (
            "text-empty.gak",
            "read_text(snapshot(from_hex(\"00\")), 0, 1, \"ascii\")",
        ),
        (
            "text-utf16-trailing.gak",
            "read_text(source, 4096, 1, \"utf16le\")",
        ),
        ("text-limit-1.gak", "read_text(source, 0, 1, \"ascii\")"),
        ("text-limit-3.gak", "read_text(source, 0, 3, \"ascii\")"),
        (
            "text-limit-4096.gak",
            "read_text(source, 0, 4096, \"ascii\")",
        ),
    ] {
        let script = s.write(name, &format!("from std.binary import from_hex, snapshot, read_text\nfrom std.bytes import repeat\nlet source = snapshot(repeat(from_hex(\"41\"), 4097))\nprint {expression}\n"));
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{name}");
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success(), "{name}");
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
    let script = s.write(
        "text-result.gak",
        "from std.binary import from_hex, snapshot, read_text\nfrom std.result import is_error, message\nfn short(source: Source, limit: i64) -> Result<str> = read_text(source, 0, limit, \"ascii\")\nlet source = snapshot(from_hex(\"41 42 43 44\"))\nprint is_error(short(source, 1))\nprint message(short(source, 1))\nprint is_error(short(source, 3))\nprint message(short(source, 3))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_strings_match_vm_for_offsets_views_and_iteration() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-strings.gak",
        "from std.binary import from_hex, snapshot, view, strings, read_text\nfrom std.bytes import repeat\nfrom std.result import ok\nfn find(source: Source, minimum: i64, encoding: str) -> Offsets = strings(source, minimum, encoding)\nlet source = snapshot(from_hex(\"00 47 41 4b 00 61 62 63 20 31 ff 58 00 59 00 00\"))\nlet part = view(source, 5, 5)\nlet many = snapshot(repeat(from_hex(\"41 00\"), 17))\nlet ascii: Offsets = find(source, 3, \"ascii\")\nlet wide = find(source, 2, \"utf16le\")\nprint ascii\nprint wide\nprint find(part, 3, \"ascii\")\nprint find(source, 4096, \"ascii\")\nprint find(many, 1, \"ascii\")\nprint ok(wide)\nfor at in ascii {\n    print at\n    print read_text(source, at, 5, \"ascii\")\n}\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_strings_errors_and_hit_limit_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    for (name, expression) in [
        ("strings-negative.gak", "strings(source, -1, \"ascii\")"),
        ("strings-zero.gak", "strings(source, 0, \"ascii\")"),
        (
            "strings-large-minimum.gak",
            "strings(source, 4097, \"ascii\")",
        ),
        ("strings-encoding.gak", "strings(source, 1, \"utf8\")"),
        ("strings-too-many.gak", "strings(source, 1, \"ascii\")"),
    ] {
        let script = s.write(name, &format!("from std.binary import from_hex, snapshot, strings\nfrom std.bytes import repeat\nlet source = snapshot(repeat(from_hex(\"41 00\"), 10001))\nprint {expression}\n"));
        let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap();
        assert!(!vm.status.success(), "{name}");
        let built = s.compile(&script);
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
        let native = Command::new(executable).output().unwrap();
        assert!(!native.status.success(), "{name}");
        assert_eq!(native.stdout, vm.stdout, "{name}");
        assert_eq!(native.stderr, vm.stderr, "{name}");
    }
    let script = s.write(
        "strings-limit.gak",
        "from std.binary import from_hex, snapshot, strings\nfrom std.bytes import repeat\nfrom std.result import is_error, message\nfn scan(source: Source) -> Result<Offsets> = strings(source, 1, \"ascii\")\nlet boundary = snapshot(repeat(from_hex(\"41 00\"), 10000))\nlet overflow = snapshot(repeat(from_hex(\"41 00\"), 10001))\nvar count = 0\nfor at in strings(boundary, 1, \"ascii\") {\n    count = count + 1\n}\nprint count\nprint strings(boundary, 1, \"utf16le\")\nprint is_error(scan(overflow))\nprint message(scan(overflow))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_hunt_matches_vm_for_patterns_views_and_overlaps() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-hunt.gak",
        "from std.binary import from_hex, snapshot, view, hunt\nfrom std.bytes import repeat, concat\nfrom std.result import ok\nfn locate(source: Source, pattern: str) -> Offsets = hunt(source, pattern)\nlet source = snapshot(from_hex(\"41 42 41 42 41 00 4f 41\"))\nlet overlap = snapshot(repeat(from_hex(\"41\"), 4))\nlet long_source = snapshot(concat(repeat(from_hex(\"41\"), 32768), from_hex(\"43\")))\nlet long_pattern = concat(repeat(from_hex(\"41\"), 16384), from_hex(\"42\"))\nprint locate(source, \"ABA\")\nprint hunt(source, from_hex(\"41 42\"))\nprint hunt(source, \"hex:4? 42\")\nprint hunt(source, \"hex:?? 41\")\nprint locate(view(source, 2, 4), \"A\")\nprint hunt(overlap, \"AA\")\nprint hunt(source, \"hex:41 42\")\nprint ok(hunt(source, \"hex:41 42\"))\nprint hunt(long_source, long_pattern)\nfor at in hunt(source, \"hex:?? 41\") {\n    print at\n}\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        "[0, 2]\n[0, 2]\n[0, 2]\n[1, 3, 6]\n[0, 2]\n[0, 1, 2]\n[0, 2]\nok([0, 2])\n[]\n1\n3\n6\n"
    );
}

#[test]
fn native_binary_hunt_errors_and_hit_limit_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-hunt-errors.gak",
        &format!(
            "from std.binary import from_hex, snapshot, hunt\nfrom std.bytes import repeat\nfrom std.result import is_error, message\nfn seek(source: Source, pattern: str) -> Result<Offsets> = hunt(source, pattern)\nlet source = snapshot(from_hex(\"41 42\"))\nlet boundary = snapshot(repeat(from_hex(\"41\"), 10000))\nlet overflow = snapshot(repeat(from_hex(\"41\"), 10001))\nvar count = 0\nfor at in hunt(boundary, \"A\") {{\n    count = count + 1\n}}\nprint count\nprint is_error(seek(overflow, \"A\"))\nprint message(seek(overflow, \"A\"))\nprint message(seek(source, \"\"))\nprint message(seek(source, \"hex:\"))\nprint message(seek(source, \"hex:0g\"))\nprint message(seek(source, \"hex:0\"))\nprint message(seek(source, \"hex:{}\"))\n",
            "??".repeat(65)
        ),
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert_eq!(String::from_utf8_lossy(&native.stdout), "10000\ntrue\ntoo many matches\nempty search pattern\nempty search pattern\ninvalid hex pattern\nhex pattern needs an even number of nibbles\nmasked hex pattern exceeds 64 bytes\n");
}

#[test]
fn native_binary_entropy_matches_vm_fixed_point_values_and_observations() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let mut program = String::from("from std.binary import from_hex, snapshot, view, entropy, value, width, offset\nfrom std.bytes import repeat\nfrom std.result import ok\nfn measure(source: Source) -> Observation = entropy(source)\nlet source = snapshot(from_hex(\"00 00 00 01\"))\nlet observed = measure(view(source, 0, 4))\nprint value(observed)\nprint width(observed)\nprint offset(observed)\nprint ok(observed)\nprint value(entropy(snapshot(from_hex(\"\"))))\nprint value(entropy(snapshot(from_hex(\"00 01\"))))\nprint value(entropy(snapshot(from_hex(\"00 01 02 03\"))))\n");
    let uniform_hex = (0_u16..=255)
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    program.push_str(&format!(
        "print value(entropy(snapshot(repeat(from_hex(\"{uniform_hex}\"), 4096))))\n"
    ));
    let mut state = 0x1234_5678_u32;
    for length in [1, 2, 3, 7, 31, 255, 1024, 4096] {
        let mut hex = String::with_capacity(length * 2);
        for _ in 0..length {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            use std::fmt::Write;
            write!(hex, "{:02x}", state >> 24).unwrap();
        }
        program.push_str(&format!(
            "print value(entropy(snapshot(from_hex(\"{hex}\"))))\n"
        ));
    }
    let script = s.write("binary-entropy.gak", &program);
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).starts_with("811\n4\n0\nok("));
    assert!(String::from_utf8_lossy(&native.stdout).contains("\n8000\n"));
}

#[test]
fn native_binary_patch_matches_vm_for_immutable_views_hashes_and_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-patch.gak",
        "from std.binary import from_hex, snapshot, view, patch, extract, size, sha256, deep\nfrom std.bytes import to_hex\nfrom std.result import ok\nfn change(source: Source, offset: i64, data: bytes) -> Source = patch(source, offset, data)\nlet root = snapshot(from_hex(\"00 41 42 43 44\"))\nlet first = view(root, 1, 4)\nlet changed = change(first, 1, from_hex(\"ff 00\"))\nlet nested = patch(view(changed, 1, 2), 0, from_hex(\"7e\"))\nprint to_hex(extract(root, 0, size(root)))\nprint to_hex(extract(first, 0, size(first)))\nprint to_hex(extract(changed, 0, size(changed)))\nprint to_hex(extract(nested, 0, size(nested)))\nprint sha256(changed) == sha256(snapshot(from_hex(\"41 ff 00 44\")))\nprint changed\nprint view(changed, 1, 2)\nprint nested\nprint deep(changed, 1, \"u16le\")\nprint ok(changed)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout)
        .starts_with("0041424344\n41424344\n41ff0044\n7e00\ntrue\n"));
}

#[test]
fn native_binary_patch_errors_and_result_capture_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-patch-errors.gak",
        "from std.binary import from_hex, snapshot, view, patch\nfrom std.result import is_error, message\nfn attempt(source: Source, offset: i64, data: bytes) -> Result<Source> = patch(source, offset, data)\nlet source = snapshot(from_hex(\"00 01\"))\nvar deep = source\nvar index = 0\nwhile index < 64 {\n    deep = view(deep, 0, 2)\n    index = index + 1\n}\nprint message(attempt(source, 0, from_hex(\"\")))\nprint message(attempt(source, -1, from_hex(\"ff\")))\nprint message(attempt(source, 2, from_hex(\"ff\")))\nprint is_error(attempt(deep, 0, from_hex(\"ff\")))\nprint message(attempt(deep, 0, from_hex(\"ff\")))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("patch data must not be empty"));
    assert!(String::from_utf8_lossy(&native.stdout).contains("Source derivation depth exceeds 64"));
}

#[test]
fn native_binary_splice_matches_vm_for_insertion_removal_views_and_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-splice.gak",
        "from std.binary import from_hex, snapshot, view, splice, patch, extract, size, sha256, deep\nfrom std.bytes import to_hex, repeat\nfn edit(source: Source, offset: i64, removed: i64, data: bytes) -> Source = splice(source, offset, removed, data)\nlet root = snapshot(from_hex(\"00 41 42 43 44\"))\nlet inserted = edit(root, 2, 0, from_hex(\"ff\"))\nlet removed = edit(inserted, 1, 2, from_hex(\"\"))\nlet replaced = edit(view(root, 1, 3), 1, 1, from_hex(\"10 20\"))\nlet nested = patch(view(replaced, 1, 2), 0, from_hex(\"7e\"))\nlet large = snapshot(repeat(from_hex(\"41\"), 1048576))\nlet grown = edit(large, 1048576, 0, from_hex(\"ff\"))\nlet changed = patch(grown, 1048576, from_hex(\"42\"))\nprint to_hex(extract(root, 0, size(root)))\nprint to_hex(extract(inserted, 0, size(inserted)))\nprint to_hex(extract(removed, 0, size(removed)))\nprint to_hex(extract(replaced, 0, size(replaced)))\nprint to_hex(extract(nested, 0, size(nested)))\nprint sha256(replaced) == sha256(snapshot(from_hex(\"41 10 20 43\")))\nprint inserted\nprint removed\nprint replaced\nprint view(replaced, 1, 2)\nprint nested\nprint deep(replaced, 1, \"u16le\")\nprint size(grown)\nprint size(changed)\nprint to_hex(extract(grown, 1048575, 2))\nprint to_hex(extract(changed, 1048575, 2))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout)
        .starts_with("0041424344\n0041ff424344\n00424344\n41102043\n7e20\ntrue\n"));
    assert!(String::from_utf8_lossy(&native.stdout).ends_with("1048577\n1048577\n41ff\n4142\n"));
}

#[test]
fn native_binary_splice_errors_and_result_capture_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-splice-errors.gak",
        "from std.binary import from_hex, snapshot, view, splice\nfrom std.result import is_error, message\nfn attempt(source: Source, offset: i64, removed: i64, data: bytes) -> Result<Source> = splice(source, offset, removed, data)\nlet source = snapshot(from_hex(\"00 01\"))\nvar deep = source\nvar index = 0\nwhile index < 64 {\n    deep = view(deep, 0, 2)\n    index = index + 1\n}\nprint message(attempt(source, 0, 0, from_hex(\"\")))\nprint message(attempt(source, -1, 0, from_hex(\"ff\")))\nprint message(attempt(source, 0, -1, from_hex(\"ff\")))\nprint message(attempt(source, 2, 1, from_hex(\"ff\")))\nprint is_error(attempt(deep, 0, 0, from_hex(\"ff\")))\nprint message(attempt(deep, 0, 0, from_hex(\"ff\")))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout)
        .contains("splice must insert or remove at least one byte"));
    assert!(String::from_utf8_lossy(&native.stdout).contains("Source derivation depth exceeds 64"));
}

#[test]
fn native_impact_matches_vm_for_observations_and_diffs() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "native-impact.gaks",
        "from std.binary import from_hex, snapshot, view, splice, deep, diff\nfn report(left: Source, right: Source) -> i64 {\n    impact deep(right, 1, \"u16le\")\n    impact diff(left, right, 3)\n    return 7\n}\nlet root = snapshot(from_hex(\"00 01 02 03\"))\nlet left = view(root, 1, 3)\nlet right = splice(left, 1, 1, from_hex(\"ff\"))\nimpact deep(root, 0, \"u8\")\nprint report(left, right)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("left_origin: \"view of sha256:"));
}

#[test]
fn native_binary_analyze_matches_vm_with_authorized_file_and_provenance() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    fs::write(s.0.join("sample.bin"), [0_u8, 0x41, 0xff, 0x42]).unwrap();
    let script = s.write(
        "binary-analyze.gak",
        "requires { file.read }\nfrom std.binary import analyze, size, deep, sha256, view\nfrom std.cli import arg, count\nlet source = analyze(arg(0), 64)\nprint count()\nprint size(source)\nprint source\nimpact deep(source, 1, \"u16le\")\nprint sha256(view(source, 1, 2))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .args(["--", "sample.bin"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .arg("--allow-read")
        .arg(&s.0)
        .args(["--", "sample.bin"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    let late_grant = Command::new(&executable)
        .arg("sample.bin")
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(late_grant.status.success());
    assert_eq!(late_grant.stdout, vm.stdout);
    let denied = Command::new(executable).arg("sample.bin").output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("file access not allowed"));
}

#[test]
#[cfg(target_os = "linux")]
fn native_binary_analyze_rejects_symlink_outside_granted_root() {
    use std::os::unix::fs::symlink;

    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let allowed = s.0.join("allowed");
    let denied = s.0.join("denied");
    fs::create_dir_all(&allowed).unwrap();
    fs::create_dir_all(&denied).unwrap();
    fs::write(denied.join("secret.bin"), b"SECRET").unwrap();
    symlink(denied.join("secret.bin"), allowed.join("link.bin")).unwrap();
    let script = s.write(
        "allowed/link-reader.gak",
        "requires { file.read }\nfrom std.binary import analyze, size\nprint size(analyze(\"link.bin\", 64))\n",
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&allowed)
        .output()
        .unwrap();
    assert!(!native.status.success());
    assert!(native.stdout.is_empty());
    assert!(String::from_utf8_lossy(&native.stderr).contains("file access not allowed"));
}

#[test]
#[cfg(target_os = "linux")]
fn native_binary_analyze_rejects_fifos_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let fifo = s.0.join("stream.pipe");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let script = s.write(
        "fifo-analyze.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.result import message\nfn attempt() -> Result<Source> = analyze(\"stream.pipe\", 16)\nprint message(attempt())\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("not a regular file"));
}

#[test]
fn native_binary_analyze_result_errors_match_vm_and_deny_sibling_files() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let allowed = s.0.join("allowed");
    fs::create_dir_all(&allowed).unwrap();
    fs::create_dir_all(s.0.join("denied")).unwrap();
    fs::write(allowed.join("small.bin"), [1_u8, 2, 3, 4]).unwrap();
    fs::write(allowed.join("empty.bin"), []).unwrap();
    fs::write(s.0.join("denied").join("foreign.bin"), [9_u8]).unwrap();
    let script = s.write(
        "allowed/analyze-errors.gaks",
        "requires { file.read }\nfrom std.binary import analyze, size\nfrom std.result import is_ok, message, recover\nfn attempt(path: str, max: i64) -> Result<Source> = analyze(path, max)\nprint is_ok(attempt(\"empty.bin\", 0))\nprint size(recover(attempt(\"small.bin\", 4), analyze(\"empty.bin\", 0)))\nprint message(attempt(\"small.bin\", -1))\nprint message(attempt(\"small.bin\", 536870913))\nprint message(attempt(\"small.bin\", 1))\nprint message(attempt(\"../denied/foreign.bin\", 4))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&allowed)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&allowed)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("file access not allowed"));
}

#[test]
fn native_binary_analyze_reads_sources_larger_than_one_mib() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    fs::write(s.0.join("large.bin"), vec![0x41_u8; 1_048_577]).unwrap();
    let script = s.write(
        "large-analyze.gak",
        "requires { file.read }\nfrom std.binary import analyze, size, sha256, extract\nfrom std.bytes import to_hex\nlet source = analyze(\"large.bin\", 1048577)\nprint size(source)\nprint sha256(source)\nprint to_hex(extract(source, 1048576, 1))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).ends_with("41\n"));
}

#[test]
fn native_binary_analyze_resolves_imported_module_directory() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    fs::create_dir_all(s.0.join("sub")).unwrap();
    fs::write(s.0.join("sub").join("payload.bin"), b"GAK").unwrap();
    s.write(
        "sub/worker.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfn load() -> Source = analyze(\"payload.bin\", 16)\n",
    );
    let script = s.write(
        "module-analyze.gak",
        "requires { file.read }\nimport \"sub/worker.gak\" as worker\nfrom std.binary import size\nprint size(worker.load())\nprint worker.load()\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_analyze_preserves_unicode_file_labels() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    fs::write(s.0.join("prüfung-研究.bin"), [0x41_u8, 0x42]).unwrap();
    let script = s.write(
        "unicode-analyze.gak",
        "requires { file.read }\nfrom std.binary import analyze, size\nlet source = analyze(\"prüfung-研究.bin\", 2)\nprint source\nprint size(source)\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-read"])
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable)
        .arg("--allow-read")
        .arg(&s.0)
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

#[test]
fn native_binary_diff_matches_vm_for_views_splices_and_length_changes() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-diff.gak",
        "from std.binary import from_hex, snapshot, view, splice, diff, diff_offsets, diff_count\nfrom std.result import ok\nfn compare(left: Source, right: Source, limit: i64) -> Diff = diff(left, right, limit)\nfn locations(report: Diff) -> Offsets = diff_offsets(report)\nlet left = snapshot(from_hex(\"00 01 02 03\"))\nlet right = snapshot(from_hex(\"00 ff 02 03 04\"))\nlet sliced = view(left, 1, 2)\nlet edited = splice(sliced, 1, 1, from_hex(\"aa bb\"))\nlet report = compare(left, right, 2)\nvar total = 0\nprint report\nprint diff(left, left, 0)\nprint diff(sliced, edited, 2)\nprint ok(diff(edited, edited, 0))\nprint diff_count(report)\nprint locations(report)\nfor at in locations(report) {\n    total = total + at\n}\nprint total\nprint diff_count(diff(left, left, 0))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("offsets: [1, 4]"));
    assert!(String::from_utf8_lossy(&native.stdout).ends_with("2\n[1, 4]\n5\n0\n"));
}

#[test]
fn native_binary_diff_limit_errors_and_result_capture_match_vm() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-diff-errors.gak",
        "from std.binary import from_hex, snapshot, diff\nfrom std.bytes import repeat\nfrom std.result import is_ok, message\nfn attempt(left: Source, right: Source, limit: i64) -> Result<Diff> = diff(left, right, limit)\nlet left = snapshot(from_hex(\"00 01\"))\nlet right = snapshot(from_hex(\"ff ff\"))\nlet boundary = snapshot(repeat(from_hex(\"ff\"), 10000))\nlet long = snapshot(repeat(from_hex(\"ff\"), 10001))\nlet empty = snapshot(from_hex(\"\"))\nprint is_ok(attempt(empty, boundary, 10000))\nprint message(attempt(left, right, 1))\nprint message(attempt(left, right, 0))\nprint message(attempt(left, right, -1))\nprint message(attempt(left, right, 10001))\nprint message(attempt(empty, long, 10000))\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(String::from_utf8_lossy(&native.stdout).contains("LimitExceeded: too many differences"));
}

#[test]
fn native_source_display_matches_vm_for_nested_views_and_containers() {
    if !gcc_available() {
        return;
    }
    let s = Sandbox::new();
    let script = s.write(
        "binary-source-display.gak",
        "from std.binary import from_hex, snapshot, view\nfrom std.result import ok\nstruct Tagged { data: Source }\nlet root = snapshot(from_hex(\"00 61 62 63 ff\"))\nlet first = view(root, 1, 3)\nlet second = view(first, 1, 2)\nvar deep: Source = snapshot(from_hex(\"00\"))\nvar index = 0\nwhile index < 64 {\n    deep = view(deep, 0, 1)\n    index = index + 1\n}\nprint root\nprint first\nprint second\nprint [first, second]\nprint ok(second)\nprint Tagged(second)\nprint deep\n",
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm"])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    let built = s.compile(&script);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(executable).output().unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
}

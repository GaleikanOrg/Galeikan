use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn direct_xrefs_calls_and_overlaps_match_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "xrefs.gak",
        "import std.binary\nimport std.asm\nimport std.list\nlet source = binary.snapshot(binary.from_hex(\"e8 02 00 00 00 eb 01 90 c3\"))\nlet lines = asm.reachable(source, 0, 0x1000u64, 64, 4)\nlet calls: List<u64> = asm.call_targets(lines)\nlet refs: List<u64> = asm.xrefs(lines, 0x1007u64)\nlet jump_refs = asm.xrefs(lines, 0x1008u64)\nlet ambiguous = asm.reachable(binary.snapshot(binary.from_hex(\"eb ff c3\")), 0, 0x2000u64, 64, 2)\nprint list.count(calls)\nprint calls[0]\nprint list.count(refs)\nprint refs[0]\nprint jump_refs[0]\nprint asm.overlap_count(lines)\nprint asm.overlap_count(ambiguous)\nprint asm.overlap_at(ambiguous, 1)\nprint asm.overlap_at(ambiguous, 0)\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "1\n4103\n1\n4096\n4101\n0\n1\ntrue\nfalse\n"
        );
    }
}

#[test]
fn self_process_references_read_bounded_memory_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "self-process.gak",
        "requires { process.inspect }\nimport std.process\nimport std.binary\nvar found = false\nfor region in process.images(process.self_pid()) {\n    if process.access(region) == \"r-x\" {\n        let key = process.reference(region, process.start_u64(region))\n        let source = process.snapshot_ref(region, key, 4)\n        print binary.size(source)\n        found = true\n        break\n    }\n}\nprint found\n",
    );
    let denied = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("process access not allowed"));
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.args(["--allow-process", "self"]).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "4\ntrue\n");
    }
    let mismatched = s.write(
        "mismatched-reference.gak",
        "requires { process.inspect }\nimport std.process\nlet region = process.at(process.images(process.self_pid()), 0)\nprint process.snapshot_ref(region, \"not-a-region-reference\", 4)\n",
    );
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(mismatched)
        .args(["--allow-process", "self"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(stderr(&rejected).contains("address reference does not match process region"));
}

#[test]
fn reachable_disassembly_and_u64_addresses_match_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "reachable.gak",
        "import std.binary\nimport std.asm\nlet source = binary.snapshot(binary.from_hex(\"75 03 90 c3 90 c3\"))\nlet lines: Disassembly = asm.reachable(source, 0, 0x8000000000000000u64, 64, 4)\nlet edges: List<u64> = asm.successors(asm.at(lines, 0))\nlet block_edges: List<u64> = asm.block_successors(lines, 0)\nlet indirect_source = binary.snapshot(binary.from_hex(\"ff e0 c3\"))\nlet indirect_lines = asm.reachable(indirect_source, 0, 0x9000u64, 64, 3)\nlet shifted = binary.snapshot(binary.from_hex(\"00 75 03 90 c3 90 c3\"))\nlet shifted_lines = asm.reachable(shifted, 1, 0x1000u64, 64, 4)\nprint asm.count(lines)\nprint asm.address_u64(asm.decode_u64(source, 0, 0x8000000000000000u64, 64))\nprint asm.target_u64(asm.at(lines, 0))\nprint asm.address_u64(asm.at(lines, 3))\nprint edges[0]\nprint edges[1]\nprint asm.block_count(lines)\nprint asm.block_start(lines, 0)\nprint asm.block_end(lines, 0)\nprint asm.block_instruction_count(lines, 1)\nprint asm.mnemonic(asm.block_instruction(lines, 1, 1))\nprint block_edges[1]\nprint asm.block_unresolved(indirect_lines, 0)\nfor instruction in lines {\n    print asm.mnemonic(instruction)\n}\nimpact shifted_lines\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let output_text = stdout(&output);
        assert!(output_text.starts_with("4\n9223372036854775808\n9223372036854775813\n9223372036854775813\n9223372036854775810\n9223372036854775813\n3\n9223372036854775808\n9223372036854775810\n2\nret\n9223372036854775813\ntrue\njne\nnop\nret\nret\n"));
        assert!(output_text.contains("range: [1..7), instructions: 4, blocks: 3"));
    }
    let bad = s.write(
        "bad-reachable.gak",
        "import std.binary\nimport std.asm\nlet source = binary.snapshot(binary.from_hex(\"eb fe\"))\nprint asm.reachable(source, 0, 4096, 64, 2)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(bad)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("expected u64, got i64"));
}

#[test]
fn unsigned_64_bit_values_match_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "unsigned.gak",
        "import std.bytes\nimport std.binary\nlet max: u64 = 18446744073709551615u64\nlet data = bytes.pack(max, \"u64le\")\nprint max\nprint 0xffffffffffffffffu64\nprint ~0u64\nprint max > 9223372036854775807u64\nprint 0x8000000000000000u64 >> 63u64\nprint 3u64 * 7u64\nprint match max { 0xffffffffffffffffu64 => 1, _ => 0 }\nprint bytes.to_hex(data)\nprint binary.value_u64(binary.deep(binary.snapshot(data), 0, \"u64le\")) == max\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "18446744073709551615\n18446744073709551615\n18446744073709551615\ntrue\n1\n21\n1\nffffffffffffffff\ntrue\n"
        );
    }
    for invalid in [
        "print 18446744073709551615u64 + 1u64\n",
        "print 0u64 - 1u64\n",
        "print 1u64 << 64u64\n",
    ] {
        let bad = s.write("overflow.gak", invalid);
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&bad)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{invalid}");
    }
}

#[test]
fn match_expression_is_lazy_typed_and_runs_in_ast_vm_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "match.gak",
        "fn code() -> i64 {\n    print 90\n    return 0x5a\n}\nprint match code() {\n    0x4d => 1 / 0,\n    0x5a => 7,\n    _ => 0,\n}\nprint match \"ELF\" {\n    \"MZ\" => 0,\n    \"ELF\" => 2,\n    _ => 3,\n}\nprint match true { false => 0, _ => 1 }\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "90\n7\n2\n1\n");
    }
    for (source, message) in [
        (
            "print match 1 { 1 => 2, 1 => 3, _ => 0 }\n",
            "duplicate match pattern",
        ),
        ("print match 1 { 1 => 2 }\n", "match arms must be separated"),
        (
            "print match 1 { \"1\" => 2, _ => 0 }\n",
            "match pattern has type",
        ),
        (
            "print match 1 { 1 => true, _ => 0 }\n",
            "match branches have different types",
        ),
    ] {
        let invalid = s.write("invalid.gak", source);
        let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(invalid)
            .output()
            .unwrap();
        assert!(!checked.status.success());
        assert!(stderr(&checked).contains(message), "{}", stderr(&checked));
    }
}

#[test]
fn bitwise_operations_match_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "bits.gak",
        "print 0xffffffffffffffff\nprint ~0\nprint 0x8000000000000000 >>> 63\nprint -8 >> 2\nprint 1 << 63\nprint 0xf0 & 0x3c | 0x80 ^ 0x01\nprint 1 + 2 << 3\nprint 4 & 3 == 0\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "-1\n-1\n1\n-2\n-9223372036854775808\n177\n24\ntrue\n"
        );
    }
    for source in ["print 1 << 64\n", "print 1 >>> -1\n"] {
        let bad = s.write("invalid.gak", source);
        for engine in ["ast", "vm"] {
            let output = s.run_engine(&bad, engine, false, &[]);
            assert!(!output.status.success());
            assert!(stderr(&output).contains("shift count must be in 0..63"));
        }
    }
}

#[test]
fn classes_and_methods_work_across_modules_ast_vm_and_bundle() {
    let s = Sandbox::new();
    s.write(
        "model.gaks",
        "class Point {\n    x: i64\n    y: i64\n    fn sum() -> i64 = self.x + self.y\n    fn shift(dx: i64, dy: i64) -> Point = Point(self.x + dx, self.y + dy)\n}\nfn build() -> Point {\n    print 99\n    return Point(1, 2)\n}\nlet origin = Point(1, 1)\n",
    );
    let script = s.write(
        "main.gak",
        "import model\nclass Tagged {\n    point: model.Point\n    label: str\n    fn total() -> i64 = self.point.sum()\n}\nlet first = model.Point(3, 4)\nlet second = first.shift(2, 5)\nlet tagged = Tagged(second, \"ok\")\nprint first.sum()\nprint second.sum()\nprint tagged.point.sum()\nprint tagged.total()\nprint model.Point(10, 1).sum()\nprint first.shift(1, 1).sum()\nprint model.build().sum()\nprint model.origin.sum()\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "7\n14\n14\n14\n11\n9\n99\n3\n2\n");
    }
    let invalid = s.write(
        "invalid.gak",
        "class Broken {\n    x: i64\n    fn x() -> i64 = self.x\n}\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(invalid)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("duplicate class member"));
}

#[test]
fn loop_control_matches_ast_vm_and_bundle_and_rejects_outside_loops() {
    let s = Sandbox::new();
    let script = s.write(
        "loops.gak",
        "import std.iter\nvar total = 0\nfn count(limit: i64) -> i64 {\n    var index = 0\n    var sum = 0\n    while index < limit {\n        index = index + 1\n        if index == 2 {\n            continue\n        }\n        if index == 4 {\n            break\n        }\n        sum = sum + index\n    }\n    return sum\n}\nfor outer in iter.range(4) {\n    if outer == 3 {\n        break\n    }\n    for inner in iter.range(5) {\n        if inner == 1 {\n            continue\n        }\n        if inner == 4 {\n            break\n        }\n        total = total + outer * 10 + inner\n    }\n}\nprint total\nprint count(7)\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (command, target, engine) in [
        ("run", script.clone(), "ast"),
        ("run", script.clone(), "vm"),
        ("exec", script.with_extension("gakb"), "vm"),
    ] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "105\n4\n");
    }
    for keyword in ["break", "continue"] {
        let invalid = s.write("invalid.gaks", &format!("if true {{\n    {keyword}\n}}\n"));
        let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(invalid)
            .output()
            .unwrap();
        assert!(!checked.status.success());
        assert!(
            stderr(&checked).contains("require a loop"),
            "{}",
            stderr(&checked)
        );
    }
}

#[test]
fn typed_structs_work_across_modules_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let model = s.write(
        "model.gaks",
        "struct Header { marker: str, offset: i64 }\nfn make() -> Header = Header(\"MZ\", 4)\n",
    );
    let script = s.write(
        "main.gak",
        "import model\nfrom model import Header as H\nstruct Tagged { header: model.Header, trusted: bool }\nlet header: model.Header = model.make()\nlet second = model.Header(\"ELF\", 8)\nlet all: List<model.Header> = [header, second]\nlet tagged = Tagged(all[1], true)\nlet direct: H = H(\"PE\", 16)\nprint header.marker\nprint header.offset\nprint tagged.header.marker\nprint direct.marker\nprint all[1].marker\nprint model.make().marker\n",
    );
    let called = call_json(&model, "make", "vm", r#"{"version":1,"args":[]}"#);
    assert!(called.status.success(), "{}", stderr(&called));
    let result: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
    assert_eq!(result["value"]["$galeikan"], "Record");
    assert_eq!(result["value"]["fields"]["marker"], "MZ");
    assert_eq!(result["value"]["fields"]["offset"], 4);
    for (command, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if command == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            fs::remove_file(s.dir.join("model.gaks")).unwrap();
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let mut process = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        process.arg(command).arg(target);
        if command == "run" {
            process.args(["--engine", engine]);
        }
        let output = process.output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "MZ\n4\nELF\nPE\nELF\nMZ\n");
    }

    let invalid = s.write(
        "invalid.gak",
        "struct Header { marker: str, offset: i64 }\nlet h = Header(42, 0)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&invalid)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(
        stderr(&checked).contains("expected str"),
        "{}",
        stderr(&checked)
    );
    s.write(
        "invalid.gak",
        "struct Header { marker: str }\nlet h = Header(\"MZ\")\nprint h.missing\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&invalid)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("unknown struct field missing"));
}

#[test]
fn serve_reuses_loaded_module_and_keeps_json_framing_after_call_error() {
    let s = Sandbox::new();
    let script = s.write(
        "serve.gak",
        "fn twice(value: i64) -> i64 {\n    print value\n    return value * 2\n}\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    for (target, engine) in [
        (script.clone(), "ast"),
        (script.clone(), "vm"),
        (script.with_extension("gakb"), "vm"),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("serve")
            .arg(&target)
            .args(["--engine", engine])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"{\"version\":1,\"function\":\"twice\",\"args\":[21]}\n\
                  {\"version\":1,\"function\":\"absent\",\"args\":[]}\n\
                  invalid json\n\
                  {\"version\":1,\"function\":\"twice\",\"args\":[22]}\n",
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        let responses = stdout(&output)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 5, "{engine}");
        assert_eq!(responses[0]["ready"], true);
        assert_eq!(responses[1]["value"], 42);
        assert_eq!(responses[1]["ok"], true);
        assert_eq!(responses[2]["ok"], false);
        assert!(responses[2]["error"].as_str().unwrap().contains("absent"));
        assert_eq!(responses[3]["ok"], false);
        assert!(responses[3]["error"]
            .as_str()
            .unwrap()
            .contains("invalid call request"));
        assert_eq!(responses[4]["value"], 44);
        assert_eq!(responses[4]["ok"], true);
        assert!(stderr(&output).contains("21"));
    }
}

#[test]
fn lab_mutations_are_deterministic_typed_and_traceable_in_ast_vm_bundle() {
    let s = Sandbox::new();
    s.write("variants.gak", "from std.lab import mutate\nfn candidates(source: Source) -> List<Source> = mutate(source, \"bitflip\", 10)\n");
    let script = s.write(
        "lab.gak",
        "requires { case.write }\nimport std.binary\nimport std.bytes\nimport std.list\nfrom variants import candidates\nlet original: Source = binary.snapshot(bytes.from_hex(\"00 ff\"))\nlet cases: List<Source> = candidates(original)\nprint list.count(cases)\nprint bytes.to_hex(binary.extract(cases[0], 0, 2))\nprint bytes.to_hex(binary.extract(cases[7], 0, 2))\nprint bytes.to_hex(binary.extract(cases[8], 0, 2))\nimpact binary.deep(cases[0], 0, \"u8\")\n",
    );
    let mut expected = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            fs::remove_file(s.dir.join("variants.gak")).unwrap();
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("lab-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with("10\n01ff\n80ff\n00fe\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let events = document["events"].clone();
        assert_eq!(
            events[0]["value"]["source_lineage"][0]["operation"],
            "capture"
        );
        assert_eq!(
            events[0]["value"]["source_lineage"][1]["operation"],
            "patch"
        );
        if let Some(previous) = &expected {
            assert_eq!(&events, previous);
        }
        expected = Some(events);
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }
}

#[test]
fn length_mutations_are_deterministic_and_keep_splice_lineage() {
    let s = Sandbox::new();
    let script = s.write(
        "length_mutations.gak",
        "requires { case.write }\nimport std.binary\nimport std.bytes\nfrom std.lab import mutate\nfrom std.list import count\nlet source = binary.snapshot(bytes.from_hex(\"41 42 43 44\"))\nlet inserted = mutate(source, 1, 2, \"insert-boundary\", 5)\nlet deleted = mutate(source, 1, 2, \"delete-byte\", 2)\nprint count(inserted)\nprint bytes.to_hex(binary.extract(inserted[0], 0, binary.size(inserted[0])))\nprint bytes.to_hex(binary.extract(inserted[4], 0, binary.size(inserted[4])))\nprint count(deleted)\nprint bytes.to_hex(binary.extract(deleted[0], 0, binary.size(deleted[0])))\nprint bytes.to_hex(binary.extract(deleted[1], 0, binary.size(deleted[1])))\nimpact binary.deep(inserted[0], 1, \"u8\")\nimpact binary.deep(deleted[1], 1, \"u8\")\n",
    );
    let mut expected_events = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("length-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.args(["--engine", engine]);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with("5\n4100424344\n4142004344\n2\n414344\n414244\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let events = &document["events"];
        assert_eq!(
            events[0]["value"]["source_lineage"][1]["operation"],
            "splice"
        );
        assert_eq!(events[0]["value"]["source_lineage"][1]["start"], 1);
        assert_eq!(events[0]["value"]["source_lineage"][1]["end"], 1);
        assert_eq!(events[0]["value"]["source_lineage"][1]["inserted_size"], 1);
        assert_eq!(events[1]["value"]["source_lineage"][1]["start"], 2);
        assert_eq!(events[1]["value"]["source_lineage"][1]["end"], 3);
        assert_eq!(events[1]["value"]["source_lineage"][1]["inserted_size"], 0);
        if let Some(previous) = &expected_events {
            assert_eq!(events, previous);
        }
        expected_events = Some(events.clone());
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }

    let empty = s.write(
        "empty-length.gak",
        "import std.binary\nimport std.lab\nimport std.list\nlet source = binary.snapshot(binary.from_hex(\"\"))\nprint list.count(lab.mutate(source, \"insert-boundary\", 4))\nprint list.count(lab.mutate(source, \"delete-byte\", 4))\n",
    );
    let output = s.run(&empty, false);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "4\n0\n");

    let oversized = s.write(
        "large-length.gak",
        "import std.binary\nimport std.bytes\nimport std.lab\nlet source = binary.snapshot(bytes.repeat(bytes.from_hex(\"00\"), 1048576))\nprint lab.mutate(source, \"insert-boundary\", 65)\n",
    );
    let output = s.run(&oversized, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("mutation corpus exceeds 67108864 materialized bytes"));
}

#[test]
fn lab_mutation_strategies_and_limits_are_explicit() {
    let s = Sandbox::new();
    let script = s.write(
        "strategies.gak",
        "import std.binary\nimport std.bytes\nfrom std.lab import mutate\nfrom std.list import count\nlet source: Source = binary.snapshot(bytes.from_hex(\"00 7f 80 ff\"))\nlet boundaries: List<Source> = mutate(source, 0, 2, \"byte-boundary\", 5)\nlet truncated: List<Source> = mutate(source, \"truncate\", 3)\nlet empty: List<Source> = mutate(source, \"bitflip\", 0)\nprint count(boundaries)\nprint bytes.to_hex(binary.extract(boundaries[0], 0, 4))\nprint bytes.to_hex(binary.extract(boundaries[3], 0, 4))\nprint binary.size(truncated[0])\nprint binary.size(truncated[2])\nprint count(empty)\n",
    );
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "5\n7f7f80ff\n000080ff\n3\n1\n0\n");
    }
    for (name, expression, message) in [
        (
            "mode",
            "lab.mutate(source, \"unknown\", 1)",
            "unknown mutation strategy",
        ),
        (
            "count",
            "lab.mutate(source, \"bitflip\", 257)",
            "mutation count exceeds 256",
        ),
        (
            "span",
            "lab.mutate(source, 4, 1, \"bitflip\", 1)",
            "out of bounds",
        ),
        (
            "truncate",
            "lab.mutate(source, 1, 1, \"truncate\", 1)",
            "requires the whole Source",
        ),
    ] {
        let script = s.write(&format!("{name}.gak"), &format!(
            "import std.binary\nimport std.lab\nlet source = binary.snapshot(binary.from_hex(\"00 11\"))\nprint {}\n", expression));
        let output = s.run(&script, false);
        assert!(!output.status.success());
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
    }
    let material = s.write(
        "material.gak",
        "import std.binary\nimport std.bytes\nimport std.lab\nlet source = binary.snapshot(bytes.repeat(bytes.from_hex(\"00\"), 1048576))\nprint lab.mutate(source, \"bitflip\", 65)\n",
    );
    let output = s.run(&material, false);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("mutation corpus exceeds 67108864 materialized bytes"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn integer_boundary_mutations_cover_endianness_and_keep_case_lineage() {
    let s = Sandbox::new();
    let script = s.write(
        "integer-boundaries.gak",
        "requires { case.write }\nimport std.binary\nimport std.bytes\nfrom std.lab import mutate\nfrom std.list import count\nlet source = binary.snapshot(bytes.from_hex(\"00 00 00 00 00 00 00 00\"))\nlet le16 = mutate(source, 0, 2, \"integer-boundary:u16le\", 5)\nlet be16 = mutate(source, 0, 2, \"integer-boundary:u16be\", 5)\nlet le32 = mutate(source, 0, 4, \"integer-boundary:u32le\", 5)\nlet be64 = mutate(source, 0, 8, \"integer-boundary:u64be\", 5)\nprint count(le16)\nprint bytes.to_hex(binary.extract(le16[0], 0, 2))\nprint bytes.to_hex(binary.extract(le16[2], 0, 2))\nprint bytes.to_hex(binary.extract(be16[0], 0, 2))\nprint bytes.to_hex(binary.extract(be16[3], 0, 2))\nprint bytes.to_hex(binary.extract(le32[2], 0, 4))\nprint bytes.to_hex(binary.extract(be64[2], 0, 8))\nprint bytes.to_hex(binary.extract(be64[3], 0, 8))\nimpact binary.deep(be64[3], 0, \"u8\")\n",
    );
    let expected = "4\n0100\n0080\n0001\nffff\n00000080\n8000000000000000\nffffffffffffffff\n";
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("integer-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with(expected), "{}", stdout(&output));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        assert_eq!(
            document["events"][0]["value"]["source_lineage"][1]["operation"],
            "patch"
        );
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }

    for (name, span, message) in [
        ("short", "0, 1", "needs at least 2 bytes"),
        ("outside", "7, 2", "out of bounds"),
    ] {
        let invalid = s.write(
            &format!("{name}.gak"),
            &format!("import std.binary\nimport std.lab\nlet source = binary.snapshot(binary.from_hex(\"00 00 00 00 00 00 00 00\"))\nprint lab.mutate(source, {span}, \"integer-boundary:u16le\", 1)\n"),
        );
        let output = s.run(&invalid, false);
        assert!(!output.status.success());
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
    }
}

#[test]
fn typed_lists_work_with_modules_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    s.write("helper.gak", "fn bump(value: i64) -> i64 = value + 1\n");
    let script = s.write("lists.gak", "from std.list import append, count\nfrom helper import bump\nfn first(values: List<i64>) -> i64 = values[0]\nlet seed: List<i64> = [2, 5]\nlet items: List<i64> = append(seed, bump(9))\nvar total: i64 = 0\nprint count(items)\nprint first(items)\nprint items[2]\nfor item in items {\n    total = total + item\n}\nprint total\n");
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "3\n2\n10\n17\n");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(s.dir.join("helper.gak")).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), "3\n2\n10\n17\n");
}

#[test]
fn list_type_and_bounds_errors_are_explicit() {
    let s = Sandbox::new();
    let mixed = s.write("mixed.gak", "let items = [1, \"two\"]\nprint items\n");
    let result = s.run(&mixed, false);
    assert!(!result.status.success());
    assert!(stderr(&result).contains("list elements must have one type"));
    let bounds = s.write("bounds.gak", "let items = [1, 2]\nprint items[2]\n");
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&bounds, engine, false, &[]);
        assert!(!result.status.success());
        assert!(stderr(&result).contains("list index out of range"));
    }
    let empty = s.write("empty.gak", "from std.list import append, concat, count\nlet empty: List<i64> = []\nlet both: List<i64> = concat(append(empty, 7), [9])\nprint count(both)\nprint both[1]\n");
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&empty, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), "2\n9\n");
    }
}

#[test]
fn python_lists_cross_the_module_bridge_in_both_engines_and_bundle() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helpers.py",
        "base = [3, 4]\ndef doubled(values):\n    return [item * 2 for item in values]\n",
    );
    let script = s.write("python_lists.gak", "requires { python.exec }\nimport py.helpers\nfrom py.helpers import base as imported\nfn doubled(values: List<i64>) -> List<i64> = helpers.doubled(values)\nlet base: List<i64> = imported\nlet output: List<i64> = doubled(base)\nprint output[0]\nprint output[1]\n");
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--allow-python").arg(python).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "6\n8\n");
    }
    s.write(
        "wrong_list.py",
        "def words():\n    return ['not-an-integer']\n",
    );
    let guarded = s.write("guarded.gak", "requires { python.exec }\nimport py.wrong_list\nvar values: List<i64> = []\nvalues = wrong_list.words()\n");
    for engine in ["ast", "vm"] {
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&guarded)
            .arg("--engine")
            .arg(engine)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            stderr(&output).contains("changes runtime type"),
            "{}",
            stderr(&output)
        );
    }
}

struct Sandbox {
    dir: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("galeikan-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, text).unwrap();
        path
    }
    fn bytes(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
    fn run(&self, script: &Path, allow: bool) -> Output {
        self.run_args(script, allow, &[])
    }
    fn run_args(&self, script: &Path, allow: bool, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        cmd.arg("run").arg(script);
        if allow {
            cmd.arg("--allow-read").arg(&self.dir);
        }
        if !args.is_empty() {
            cmd.arg("--").args(args);
        }
        cmd.output().unwrap()
    }
    fn run_engine(&self, script: &Path, engine: &str, allow: bool, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        cmd.arg("run").arg(script).arg("--engine").arg(engine);
        if allow {
            cmd.arg("--allow-read").arg(&self.dir);
        }
        if !args.is_empty() {
            cmd.arg("--").args(args);
        }
        cmd.output().unwrap()
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn elf64_dynamic_symbol_fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x300];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&0x100_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
    let dynsym = 0x140;
    bytes[dynsym + 4..dynsym + 8].copy_from_slice(&11_u32.to_le_bytes());
    bytes[dynsym + 24..dynsym + 32].copy_from_slice(&0x1c0_u64.to_le_bytes());
    bytes[dynsym + 32..dynsym + 40].copy_from_slice(&72_u64.to_le_bytes());
    bytes[dynsym + 40..dynsym + 44].copy_from_slice(&2_u32.to_le_bytes());
    bytes[dynsym + 56..dynsym + 64].copy_from_slice(&24_u64.to_le_bytes());
    let dynstr = 0x180;
    bytes[dynstr + 4..dynstr + 8].copy_from_slice(&3_u32.to_le_bytes());
    bytes[dynstr + 24..dynstr + 32].copy_from_slice(&0x220_u64.to_le_bytes());
    bytes[dynstr + 32..dynstr + 40].copy_from_slice(&14_u64.to_le_bytes());
    bytes[0x1d8..0x1dc].copy_from_slice(&1_u32.to_le_bytes());
    bytes[0x1dc] = 0x12;
    bytes[0x1f0..0x1f4].copy_from_slice(&6_u32.to_le_bytes());
    bytes[0x1f4] = 0x12;
    bytes[0x1f6..0x1f8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x1f8..0x200].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[0x200..0x208].copy_from_slice(&12_u64.to_le_bytes());
    bytes[0x220..0x22e].copy_from_slice(b"\0puts\0inspect\0");
    bytes
}

#[test]
fn case_export_preserves_structured_impact_across_engines_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "case.gak",
        "requires { case.write }\nimport std.binary\nlet source = binary.snapshot(binary.from_hex(\"47 41 4b 00\"))\nimpact binary.deep(source, 0, \"u16le\")\n",
    );
    let mut hashes = Vec::new();
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(&target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(String::from_utf8_lossy(&output.stdout).contains("impact {"));
        let report: serde_json::Value = serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        assert_eq!(report["format"], "galeikan.case");
        assert_eq!(report["version"], 3);
        assert_eq!(report["blobs"].as_array().unwrap().len(), 3);
        assert_eq!(report["artifacts"].as_array().unwrap().len(), 1);
        assert_eq!(report["entry"], "case.gak");
        assert_eq!(report["engine"], engine);
        assert_eq!(report["effects"], serde_json::json!(["case.write"]));
        assert_eq!(report["events"][0]["module"], "case.gak");
        assert_eq!(report["events"][0]["line"], 4);
        assert_eq!(report["events"][0]["value"]["$galeikan"], "Observation");
        assert_eq!(report["events"][0]["value"]["value"], 0x4147);
        assert_eq!(report["events"].as_array().unwrap().len(), 1);
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
        assert_eq!(stdout(&verified), "Case verified: 1 events, 3 blobs\n");
        hashes.push(report["program_sha256"].as_str().unwrap().to_owned());
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
}

#[test]
fn case_v3_archives_source_python_and_bundle_inputs() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write("tool.py", "def marker():\n    return 42\n");
    s.write(
        "helper.gak",
        "requires { python.exec }\nimport py.tool\nfn marker() -> i64 = tool.marker()\n",
    );
    let script = s.write("main.gak", "requires { case.write, python.exec }\nimport std.binary\nimport helper\nlet source = binary.snapshot(binary.from_hex(\"47 41\"))\nprint helper.marker()\nimpact binary.deep(source, 0, \"u16le\")\n");
    let source_case = s.dir.join("source-case.json");
    let source = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--case")
        .arg(&source_case)
        .arg("--allow-python")
        .arg(python)
        .arg("--")
        .arg("sample.bin")
        .output()
        .unwrap();
    assert!(source.status.success(), "{}", stderr(&source));
    assert!(stdout(&source).starts_with("42\n"));
    let source_doc: serde_json::Value =
        serde_json::from_slice(&fs::read(&source_case).unwrap()).unwrap();
    assert_eq!(source_doc["version"], 3);
    assert_eq!(source_doc["program_mode"], "source");
    assert_eq!(source_doc["arguments"], serde_json::json!(["sample.bin"]));
    let source_artifacts = source_doc["artifacts"].as_array().unwrap();
    assert_eq!(source_artifacts.len(), 3);
    assert!(source_artifacts
        .iter()
        .any(|item| item["kind"] == "galeikan.source" && item["path"] == "main.gak"));
    assert!(source_artifacts
        .iter()
        .any(|item| item["kind"] == "galeikan.source" && item["path"] == "helper.gak"));
    assert!(source_artifacts
        .iter()
        .any(|item| item["kind"] == "python.module" && item["path"] == "tool.py"));
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&source_case)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));

    let mut altered_source = source_doc.clone();
    altered_source["program_sha256"] = serde_json::json!("0".repeat(64));
    fs::write(&source_case, serde_json::to_vec(&altered_source).unwrap()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&source_case)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        stderr(&rejected).contains("program blob hash differs"),
        "{}",
        stderr(&rejected)
    );
    fs::write(&source_case, serde_json::to_vec(&source_doc).unwrap()).unwrap();

    let mut altered_path = source_doc.clone();
    altered_path["artifacts"][0]["path"] = serde_json::json!("../outside.gak");
    fs::write(&source_case, serde_json::to_vec(&altered_path).unwrap()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&source_case)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        stderr(&rejected).contains("invalid or duplicate identity"),
        "{}",
        stderr(&rejected)
    );
    fs::write(&source_case, serde_json::to_vec(&source_doc).unwrap()).unwrap();

    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("helper.gak")).unwrap();
    let bundle_case = s.dir.join("bundle-case.json");
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--case")
        .arg(&bundle_case)
        .arg("--allow-python")
        .arg(python)
        .arg("--")
        .arg("sample.bin")
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&source), stdout(&bundled));
    let bundle_doc: serde_json::Value =
        serde_json::from_slice(&fs::read(&bundle_case).unwrap()).unwrap();
    assert_eq!(bundle_doc["program_mode"], "bundle");
    assert_eq!(bundle_doc["program_sha256"], source_doc["program_sha256"]);
    assert_eq!(bundle_doc["arguments"], source_doc["arguments"]);
    let bundle_artifacts = bundle_doc["artifacts"].as_array().unwrap();
    assert_eq!(bundle_artifacts.len(), 2);
    assert!(bundle_artifacts
        .iter()
        .any(|item| item["kind"] == "galeikan.bundle" && item["path"] == "main.gakb"));
    assert!(bundle_artifacts
        .iter()
        .any(|item| item["kind"] == "python.module" && item["path"] == "tool.py"));
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&bundle_case)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));

    let mut altered = bundle_doc;
    altered["program_sha256"] = serde_json::json!("0".repeat(64));
    fs::write(&bundle_case, serde_json::to_vec(&altered).unwrap()).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&bundle_case)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        stderr(&rejected).contains("program blob hash differs"),
        "{}",
        stderr(&rejected)
    );
}

#[test]
fn case_v3_detects_python_module_changes_before_execution() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write("changing.py", "def change():\n    with open(__file__, 'a', encoding='utf-8') as file:\n        file.write('\\n# changed\\n')\n    return 1\ndef value():\n    return 2\n");
    let script = s.write("change.gak", "requires { case.write, python.exec }\nimport py.changing\nprint changing.change()\nprint changing.value()\n");
    let case = s.dir.join("changed.json");
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--case")
        .arg(&case)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("Python module changed after case snapshot"),
        "{}",
        stderr(&result)
    );
    assert!(!case.exists());
}

#[test]
fn case_verifier_still_accepts_version_2_empty_cases() {
    let s = Sandbox::new();
    let legacy = s.write(
        "legacy.json",
        "{\"format\":\"galeikan.case\",\"version\":2,\"events\":[],\"blobs\":[]}",
    );
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(legacy)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));
}

#[test]
fn case_export_requires_declaration_and_never_overwrites() {
    let s = Sandbox::new();
    let case = s.dir.join("case.json");
    let plain = s.write("plain.gak", "print 1\n");
    let denied = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&plain)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("case.write"));
    assert!(!case.exists());
    assert!(!s.dir.join("case.json.blobs").exists());

    let failing = s.write("failing.gak", "requires { case.write }\nprint 1 / 0\n");
    let failed = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&failing)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!case.exists());
    assert!(!s.dir.join("case.json.blobs").exists());

    fs::write(&case, b"keep").unwrap();
    let collision = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&failing)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert!(stderr(&collision).contains("already exists"));
    assert_eq!(fs::read(&case).unwrap(), b"keep");

    let archive = s.dir.join("reserved.json.blobs");
    fs::create_dir(&archive).unwrap();
    let reserved = s.dir.join("reserved.json");
    let collision = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(s.write("valid.gak", "requires { case.write }\nprint 42\n"))
        .arg("--case")
        .arg(&reserved)
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert!(stderr(&collision).contains("case archive already exists"));
    assert!(!reserved.exists());
}

#[test]
fn empty_case_archives_program_and_can_be_verified() {
    let s = Sandbox::new();
    let script = s.write("empty.gak", "requires { case.write }\nprint 42\n");
    let case = s.dir.join("empty.json");
    let created = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(created.status.success(), "{}", stderr(&created));
    assert!(s.dir.join("empty.json.blobs").exists());
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert_eq!(stdout(&verified), "Case verified: 0 events, 2 blobs\n");
}

#[test]
fn case_export_records_complete_source_lineage() {
    let s = Sandbox::new();
    let script = s.write(
        "lineage.gak",
        "requires { case.write }\n\
         import std.binary\n\
         let root = binary.snapshot(binary.from_hex(\"00 11 22 33 44\"))\n\
         let view = binary.view(root, 1, 3)\n\
         let patched = binary.patch(view, 1, binary.from_hex(\"ff\"))\n\
         let nested = binary.view(patched, 1, 2)\n\
         impact binary.deep(nested, 0, \"u16le\")\n\
         impact binary.diff(view, patched, 8)\n",
    );
    let case = s.dir.join("lineage.json");
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
    let observation = &report["events"][0]["value"];
    assert_eq!(observation["value"], 0x33ff);
    let lineage = observation["source_lineage"].as_array().unwrap();
    assert_eq!(lineage.len(), 4);
    assert_eq!(lineage[0]["operation"], "capture");
    assert_eq!(lineage[0]["origin"], "memory");
    assert_eq!(lineage[1]["operation"], "view");
    assert_eq!(lineage[1]["start"], 1);
    assert_eq!(lineage[1]["end"], 4);
    assert_eq!(lineage[2]["operation"], "patch");
    assert_eq!(lineage[2]["start"], 1);
    assert_eq!(lineage[2]["end"], 2);
    assert_eq!(lineage[3]["operation"], "view");
    assert_eq!(lineage[3]["start"], 1);
    assert_eq!(lineage[3]["end"], 3);
    for index in 1..lineage.len() {
        assert_eq!(
            lineage[index]["parent_sha256"],
            lineage[index - 1]["sha256"]
        );
    }
    assert_eq!(
        lineage[2]["replacement_sha256"],
        sha2::Sha256::digest([0xff])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let diff = &report["events"][1]["value"];
    assert_eq!(diff["left_lineage"].as_array().unwrap().len(), 2);
    assert_eq!(diff["right_lineage"].as_array().unwrap().len(), 3);

    let vm_case = s.dir.join("lineage-vm.json");
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .arg("--case")
        .arg(&vm_case)
        .output()
        .unwrap();
    assert!(vm.status.success(), "{}", stderr(&vm));
    let vm_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&vm_case).unwrap()).unwrap();
    assert_eq!(report["events"], vm_report["events"]);

    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle_case = s.dir.join("lineage-bundle.json");
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--case")
        .arg(&bundle_case)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    let bundle_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&bundle_case).unwrap()).unwrap();
    assert_eq!(report["events"], bundle_report["events"]);
    for path in [&case, &vm_case, &bundle_case] {
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(path)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }
}

#[test]
fn case_verifier_rejects_tampered_blobs_and_lineage() {
    let s = Sandbox::new();
    let script = s.write(
        "case.gak",
        "requires { case.write }\nimport std.binary\nlet source = binary.snapshot(binary.from_hex(\"00 11 22\"))\nimpact binary.deep(binary.view(source, 1, 2), 0, \"u16le\")\n",
    );
    let path = s.dir.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--case")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let original = fs::read(&path).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let hash = document["events"][0]["value"]["source_lineage"][0]["sha256"]
        .as_str()
        .unwrap();
    let blob = s.dir.join("report.json.blobs").join(format!("{hash}.bin"));
    let captured = fs::read(&blob).unwrap();
    assert_eq!(captured, [0, 0x11, 0x22]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [&path, &blob] {
            assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o077, 0);
        }
        assert_eq!(
            fs::metadata(s.dir.join("report.json.blobs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    fs::write(&blob, [0xff, 0x11, 0x22]).unwrap();
    let changed = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        stderr(&changed).contains("SHA-256 mismatch"),
        "{}",
        stderr(&changed)
    );
    fs::write(&blob, &captured).unwrap();
    let mut tampered = document;
    tampered["events"][0]["value"]["source_lineage"][1]["end"] = serde_json::json!(99);
    fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let changed = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        stderr(&changed).contains("out of bounds"),
        "{}",
        stderr(&changed)
    );
    fs::write(&path, &original).unwrap();
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&path)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));
}

#[test]
fn audit_hunt_creates_pattern_findings_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "pattern.gak",
        "requires { case.write }\n\
         from std.binary import snapshot, from_hex\n\
         from std.audit import hunt, passed, failed\n\
         let source: Source = snapshot(from_hex(\"4d 5a 90 00 4d 5a 91 00\"))\n\
         let present: Finding = hunt(source, \"hex:4d 5a 9? 00\", \"pe.header.marker\")\n\
         let absent: Finding = hunt(source, from_hex(\"ff ee\"), \"marker.absent\")\n\
         impact present\n\
         impact absent\n\
         print passed(present)\n\
         print failed(absent)\n",
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let mut baseline = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let case = s.dir.join(format!("pattern-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(if mode == "exec" {
            script.with_extension("gakb")
        } else {
            script.clone()
        });
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("matches: 2"), "{stdout}");
        assert!(stdout.ends_with("true\ntrue\n") || stdout.ends_with("true\r\ntrue\r\n"));
        let report: serde_json::Value = serde_json::from_slice(&fs::read(case).unwrap()).unwrap();
        let present = &report["events"][0]["value"];
        let absent = &report["events"][1]["value"];
        assert_eq!(present["kind"], "pattern");
        assert_eq!(present["passed"], true);
        assert_eq!(present["pattern_kind"], "hex");
        assert_eq!(present["pattern_width"], 4);
        assert_eq!(present["offsets"], serde_json::json!([0, 4]));
        assert_eq!(present["source_lineage"][0]["operation"], "capture");
        assert_eq!(absent["passed"], false);
        assert_eq!(absent["pattern_kind"], "bytes");
        assert_eq!(absent["count"], 0);
        assert_eq!(absent["offsets"], serde_json::json!([]));
        if let Some(expected) = &baseline {
            assert_eq!(expected, &report["events"]);
        } else {
            baseline = Some(report["events"].clone());
        }
    }
}

#[test]
fn audit_hunt_rejects_invalid_and_excessive_patterns() {
    let s = Sandbox::new();
    let oversized = "41".repeat(4097);
    for (name, pattern, error) in [
        ("empty", "\"\"".to_owned(), "empty search pattern"),
        (
            "malformed",
            "\"hex:4?f\"".to_owned(),
            "even number of nibbles",
        ),
        (
            "oversized",
            format!("\"hex:{oversized}\""),
            "search pattern exceeds 4096 bytes",
        ),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!(
                "import std.binary\nimport std.audit\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nimpact audit.hunt(source, {pattern}, \"test.rule\")\n"
            ),
        );
        let output = s.run(&script, false);
        assert!(!output.status.success());
        assert!(stderr(&output).contains(error), "{}", stderr(&output));
    }
}

#[test]
fn deeply_nested_imports_fail_with_a_diagnostic() {
    let s = Sandbox::new();
    for depth in 0..65 {
        let source = if depth == 64 {
            "fn value() -> i64 = 1\n".to_string()
        } else {
            format!("import m{}\n", depth + 1)
        };
        s.write(&format!("m{depth}.gak"), &source);
    }
    let script = s.dir.join("m0.gak");
    let output = s.run(&script, false);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("module import depth exceeds 64"),
        "{}",
        stderr(&output)
    );
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn call_json(script: &Path, function: &str, engine: &str, request: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "call",
            script.to_str().unwrap(),
            function,
            "--engine",
            engine,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn local_http_server(responses: Vec<&'static [u8]>) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        for response in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let (mut client, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("HTTP test server accept failed: {error}"),
                }
            };
            client.set_nonblocking(false).unwrap();
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = client.read(&mut chunk).unwrap();
                assert!(count > 0, "HTTP test client closed before headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(
                    request.len() <= 16_384,
                    "HTTP test request headers too large"
                );
            }
            assert!(request.starts_with(b"GET /"), "unexpected HTTP method");
            client.write_all(response).unwrap();
        }
    });
    (port, server)
}

fn local_http_post_server(count: usize) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for _ in 0..count {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let (mut client, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("HTTP POST test accept failed: {error}"),
                }
            };
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = client.read(&mut chunk).unwrap();
                assert!(count > 0, "HTTP request ended early");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 16_384, "HTTP test request too large");
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    if request.len() >= header_end + 4 + 3 {
                        break;
                    }
                }
            }
            assert!(request.starts_with(b"POST /probe HTTP/1.1\r\n"));
            let lower = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(lower.contains("x-research: galeikan\r\n"));
            assert!(lower.contains("content-length: 3\r\n"));
            assert!(request.ends_with(b"GAK"));
            client.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\nX-Trace: alpha\r\nX-Trace: beta\r\nConnection: close\r\n\r\nMZ!").unwrap();
        }
    });
    (port, server)
}

#[test]
fn json_call_invokes_module_functions_without_corrupting_machine_output() {
    let s = Sandbox::new();
    s.write(
        "helper.gak",
        "import std.binary\nfn signature(source: Source) -> Observation = binary.deep(source, 0, \"u16le\")\n",
    );
    let script = s.write(
        "main.gak",
        "import std.binary\nimport helper as h\nfn noisy(n: i64) -> i64 {\n  print \"function output\"\n  return n * 2\n}\nfn inspect(data: bytes) -> Observation = h.signature(binary.snapshot(data))\nfn echo(data: bytes) -> bytes = data\nfn fail() -> Result<i64> = 1 / 0\nprint \"root output must not run\"\n",
    );
    for engine in ["ast", "vm"] {
        let noisy = call_json(&script, "noisy", engine, r#"{"version":1,"args":[21]}"#);
        assert!(noisy.status.success(), "{}", stderr(&noisy));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&noisy.stdout).unwrap(),
            serde_json::json!({"version": 1, "value": 42})
        );
        assert_eq!(stderr(&noisy), "function output\n");

        let inspected = call_json(
            &script,
            "inspect",
            engine,
            r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"4d5a"}]}"#,
        );
        assert!(inspected.status.success(), "{}", stderr(&inspected));
        let result: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(result["value"]["$galeikan"], "Observation");
        assert_eq!(result["value"]["value"], 0x5a4d);
        assert_eq!(result["value"]["offset"], 0);
        assert_eq!(result["value"]["width"], 2);

        let bytes = call_json(
            &script,
            "echo",
            engine,
            r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"00ff"}]}"#,
        );
        assert!(bytes.status.success(), "{}", stderr(&bytes));
        let result: serde_json::Value = serde_json::from_slice(&bytes.stdout).unwrap();
        assert_eq!(result["value"]["hex"], "00ff");

        let failed = call_json(&script, "fail", engine, r#"{"version":1,"args":[]}"#);
        assert!(failed.status.success(), "{}", stderr(&failed));
        let result: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
        assert_eq!(result["value"]["$galeikan"], "Result");
        assert_eq!(result["value"]["ok"], false);
        assert!(result["value"]["error"]
            .as_str()
            .unwrap()
            .contains("division by zero"));
    }
    let invalid = call_json(&script, "noisy", "ast", r#"{"version":1,"args":[true]}"#);
    assert!(!invalid.status.success());
    assert!(
        stderr(&invalid).contains("expects i64"),
        "{}",
        stderr(&invalid)
    );

    let expected = call_json(
        &script,
        "inspect",
        "vm",
        r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"4d5a"}]}"#,
    );
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("helper.gak")).unwrap();
    let bundle = script.with_extension("gakb");
    let compiled = call_json(
        &bundle,
        "inspect",
        "vm",
        r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"4d5a"}]}"#,
    );
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(compiled.stdout, expected.stdout);
    let wrong_engine = call_json(
        &bundle,
        "inspect",
        "ast",
        r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"4d5a"}]}"#,
    );
    assert!(!wrong_engine.status.success());
    assert!(stderr(&wrong_engine).contains("VM engine"));
}

#[test]
fn json_call_keeps_file_read_permission_checks() {
    let s = Sandbox::new();
    s.bytes("sample.bin", b"MZ");
    let script = s.write(
        "reader.gak",
        "requires { file.read }\nimport std.binary\nfn header(path: str) -> Observation = binary.deep(binary.analyze(path, 2), 0, \"u16le\")\n",
    );
    let request = r#"{"version":1,"args":["sample.bin"]}"#;
    let denied = call_json(&script, "header", "ast", request);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("file access not allowed"));
    assert!(denied.stdout.is_empty());

    let mut child = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("call")
        .arg(&script)
        .arg("header")
        .arg("--allow-read")
        .arg(&s.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let allowed = child.wait_with_output().unwrap();
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    let result: serde_json::Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(result["value"]["value"], 0x5a4d);

    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    fs::remove_file(&script).unwrap();
    let bundle = script.with_extension("gakb");
    let denied = call_json(&bundle, "header", "vm", request);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("file access not allowed"));
    assert!(denied.stdout.is_empty());

    let mut child = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("call")
        .arg(&bundle)
        .arg("header")
        .arg("--allow-read")
        .arg(&s.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let allowed = child.wait_with_output().unwrap();
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    let result: serde_json::Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(result["value"]["value"], 0x5a4d);
}

#[test]
fn locked_local_packages_are_reproducible_and_embedded_in_bundles() {
    let s = Sandbox::new();
    let manifest = s.write(
        "galeikan.json",
        "{\"version\":1,\"dependencies\":{\"codec\":\"vendor/codec\"}}\n",
    );
    let helper = s.write(
        "vendor/codec/helper.gak",
        "fn twice(value: i64) -> i64 = value * 2\n",
    );
    let module = s.write(
        "vendor/codec/main.gak",
        "import helper\nfn answer() -> i64 = helper.twice(21)\n",
    );
    let script = s.write("src/main.gak", "import pkg.codec\nprint codec.answer()\n");
    let check = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(
        stderr(&check).contains("galeikan.lock"),
        "{}",
        stderr(&check)
    );

    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(lock.status.success(), "{}", stderr(&lock));
    let locked = fs::read(s.dir.join("galeikan.lock")).unwrap();
    let lock_again = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(lock_again.status.success(), "{}", stderr(&lock_again));
    assert_eq!(locked, fs::read(s.dir.join("galeikan.lock")).unwrap());

    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), "42\n");
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    fs::write(&helper, "fn twice(value: i64) -> i64 = value * 3\n").unwrap();
    let changed = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        stderr(&changed).contains("differs from galeikan.lock"),
        "{}",
        stderr(&changed)
    );

    fs::remove_file(script.clone()).unwrap();
    fs::remove_file(helper).unwrap();
    fs::remove_file(module).unwrap();
    fs::remove_file(manifest).unwrap();
    fs::remove_file(s.dir.join("galeikan.lock")).unwrap();
    let bundle = script.with_extension("gakb");
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), "42\n");
}

#[test]
fn package_paths_cannot_escape_project() {
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":1,\"dependencies\":{\"outside\":\"../outside\"}}\n",
    );
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("invalid dependency path"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn versioned_transitive_packages_run_and_lock_reproducibly() {
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":2,\"dependencies\":{\"parser\":{\"path\":\"vendor/parser\",\"version\":\"1.2.3\"}}}\n",
    );
    s.write(
        "vendor/parser/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"parser\",\"version\":\"1.2.3\"},\"dependencies\":{\"bits\":{\"path\":\"vendor/bits\",\"version\":\"0.4.0\"}}}\n",
    );
    s.write(
        "vendor/parser/main.gak",
        "import pkg.bits\nfn answer() -> i64 = bits.twice(21)\n",
    );
    s.write(
        "vendor/bits/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"bits\",\"version\":\"0.4.0\"},\"dependencies\":{}}\n",
    );
    let bits = s.write("vendor/bits/main.gak", "fn twice(n: i64) -> i64 = n * 2\n");
    let script = s.write("src/main.gak", "import pkg.parser\nprint parser.answer()\n");
    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(lock.status.success(), "{}", stderr(&lock));
    let first = fs::read(s.dir.join("galeikan.lock")).unwrap();
    let contents: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(contents["version"], 2);
    assert_eq!(contents["roots"], serde_json::json!(["parser"]));
    assert_eq!(
        contents["dependencies"]["parser"]["dependencies"],
        serde_json::json!(["bits"])
    );
    assert_eq!(contents["dependencies"]["bits"]["version"], "0.4.0");
    let relock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(relock.status.success(), "{}", stderr(&relock));
    assert_eq!(first, fs::read(s.dir.join("galeikan.lock")).unwrap());
    let mut tampered: serde_json::Value = serde_json::from_slice(&first).unwrap();
    tampered["dependencies"]["parser"]["dependencies"] = serde_json::json!([]);
    fs::write(
        s.dir.join("galeikan.lock"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(stderr(&rejected).contains("differs from galeikan.lock"));
    fs::write(s.dir.join("galeikan.lock"), &first).unwrap();
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), "42\n");
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundle.status.success(), "{}", stderr(&bundle));
    assert_eq!(stdout(&bundle), "42\n");
    fs::write(bits, "fn twice(n: i64) -> i64 = n * 3\n").unwrap();
    let changed = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        stderr(&changed).contains("differs from galeikan.lock"),
        "{}",
        stderr(&changed)
    );
}

#[test]
fn versioned_package_rejects_cycles_and_identity_mismatch() {
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":2,\"dependencies\":{\"one\":{\"path\":\"vendor/one\",\"version\":\"1.0.0\"}}}\n",
    );
    let one = s.write(
        "vendor/one/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"one\",\"version\":\"1.0.0\"},\"dependencies\":{\"two\":{\"path\":\"vendor/two\",\"version\":\"1.0.0\"}}}\n",
    );
    s.write("vendor/one/main.gak", "fn value() -> i64 = 1\n");
    s.write(
        "vendor/two/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"two\",\"version\":\"1.0.0\"},\"dependencies\":{\"one\":{\"path\":\"vendor/one\",\"version\":\"1.0.0\"}}}\n",
    );
    s.write("vendor/two/main.gak", "fn value() -> i64 = 2\n");
    let cycle = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(!cycle.status.success());
    assert!(
        stderr(&cycle).contains("cyclic package dependency"),
        "{}",
        stderr(&cycle)
    );
    fs::write(
        one,
        "{\"version\":2,\"package\":{\"name\":\"one\",\"version\":\"1.0.1\"},\"dependencies\":{}}\n",
    ).unwrap();
    let mismatch = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(
        stderr(&mismatch).contains("identity/version does not match"),
        "{}",
        stderr(&mismatch)
    );
}

#[test]
fn versioned_package_rejects_conflicting_transitive_versions() {
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":2,\"dependencies\":{\"one\":{\"path\":\"vendor/one\",\"version\":\"1.0.0\"},\"two\":{\"path\":\"vendor/two\",\"version\":\"1.0.0\"}}}\n",
    );
    for (name, version) in [("one", "1.0.0"), ("two", "1.0.0")] {
        s.write(
            &format!("vendor/{name}/main.gak"),
            "fn value() -> i64 = 1\n",
        );
        let shared_version = if name == "one" { "1.0.0" } else { "2.0.0" };
        s.write(
            &format!("vendor/{name}/galeikan.json"),
            &format!(
                "{{\"version\":2,\"package\":{{\"name\":\"{name}\",\"version\":\"{version}\"}},\"dependencies\":{{\"shared\":{{\"path\":\"vendor/shared\",\"version\":\"{shared_version}\"}}}}}}\n"
            ),
        );
    }
    s.write(
        "vendor/shared/galeikan.json",
        "{\"version\":2,\"package\":{\"name\":\"shared\",\"version\":\"1.0.0\"},\"dependencies\":{}}\n",
    );
    s.write("vendor/shared/main.gak", "fn value() -> i64 = 1\n");
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("conflicting package shared"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn locked_package_can_call_its_own_python_module() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "galeikan.json",
        "{\"version\":1,\"dependencies\":{\"labels\":\"vendor/labels\"}}\n",
    );
    s.write(
        "vendor/labels/helper.py",
        "def up(text):\n    return text.upper()\n",
    );
    s.write(
        "vendor/labels/main.gak",
        "requires { python.exec }\nimport py.helper\nfn label(text: str) -> str = helper.up(text)\n",
    );
    let script = s.write(
        "src/main.gak",
        "requires { python.exec }\nimport pkg.labels\nprint labels.label(\"galeikan\")\n",
    );
    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(lock.status.success(), "{}", stderr(&lock));
    let run = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    assert_eq!(stdout(&run), "GALEIKAN\n");
    let second = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(stdout(&second), "GALEIKAN\n");
    assert!(!s.dir.join("vendor/labels/__pycache__").exists());
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    fs::remove_file(s.dir.join("vendor/labels/main.gak")).unwrap();
    let exec = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(exec.status.success(), "{}", stderr(&exec));
    assert_eq!(stdout(&exec), "GALEIKAN\n");
}

#[test]
fn compiled_bundle_runs_without_gak_sources_and_keeps_permissions() {
    let s = Sandbox::new();
    s.bytes("sample.bin", b"GAK\0");
    let helper = s.write("helper.gak", "import std.binary\nfn signature(source: Source) -> Observation = binary.deep(source, 0, \"u16le\")\n");
    let script = s.write("main.gak", "requires { file.read }\nimport std.binary\nimport helper\nlet source = binary.analyze(\"sample.bin\", 8)\nimpact helper.signature(source)\nprint binary.sha256(source)\n");
    let expected = s.run_engine(&script, "vm", true, &[]);
    assert!(expected.status.success(), "{}", stderr(&expected));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    assert!(bundle.exists());
    fs::remove_file(script).unwrap();
    fs::remove_file(helper).unwrap();
    let denied = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(
        stderr(&denied).contains("file access not allowed"),
        "{}",
        stderr(&denied)
    );
    let actual = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-read")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(actual.status.success(), "{}", stderr(&actual));
    assert_eq!(stdout(&expected), stdout(&actual));
    let mut damaged = fs::read(&bundle).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&bundle, damaged).unwrap();
    let invalid = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-read")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(
        stderr(&invalid).contains("checksum"),
        "{}",
        stderr(&invalid)
    );
}

#[test]
fn bytecode_vm_matches_ast_for_modules_results_and_lazy_branches() {
    let s = Sandbox::new();
    s.bytes("sample.bin", b"GAK\0");
    s.write(
        "helper.gak",
        "import std.binary\nfn signature(source: Source) -> Observation = binary.deep(source, 0, \"u16le\")\n",
    );
    let script = s.write(
        "engines.gak",
        "requires { file.read }\nimport std.binary\nimport std.audit\nimport std.cli\nimport helper\nlet source = binary.analyze(\"sample.bin\", 8)\nfn inspect(limit: i64) -> Result<Finding> {\n    let observation = helper.signature(source)\n    return audit.bound(observation, 0, limit, \"signature.range\")\n}\nprint if cli.int(0) == 1 { 42 } else { 1 / 0 }\nimpact inspect(65535)?\nprint binary.sha256(source)\n",
    );
    let ast = s.run_engine(&script, "ast", true, &["1"]);
    let vm = s.run_engine(&script, "vm", true, &["1"]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(ast.status.code(), vm.status.code());
    assert_eq!(stdout(&ast), stdout(&vm));
    assert_eq!(stderr(&ast), stderr(&vm));

    let ast_else = s.run_engine(&script, "ast", true, &["0"]);
    let vm_else = s.run_engine(&script, "vm", true, &["0"]);
    assert!(!ast_else.status.success());
    assert_eq!(ast_else.status.code(), vm_else.status.code());
    assert_eq!(stderr(&ast_else), stderr(&vm_else));

    let failing = s.write(
        "engines-error.gak",
        "fn fail() -> Result<i64> = 1 / 0\nprint fail()?\n",
    );
    let ast = s.run_engine(&failing, "ast", false, &[]);
    let vm = s.run_engine(&failing, "vm", false, &[]);
    assert!(!ast.status.success());
    assert_eq!(ast.status.code(), vm.status.code());
    assert_eq!(stderr(&ast), stderr(&vm));

    let unknown = s.run_engine(&script, "other", true, &[]);
    assert_eq!(unknown.status.code(), Some(2));
}

#[test]
fn bytecode_vm_matches_published_examples() {
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in [
        "binary_diff.gak",
        "audit_header.gak",
        "result_probe.gak",
        "analyze.gak",
    ] {
        let script = examples.join(name);
        let run = |engine| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
            command.arg("run").arg(&script).arg("--engine").arg(engine);
            if name == "analyze.gak" {
                command.arg("--allow-read").arg(&examples);
            }
            command.output().unwrap()
        };
        let ast = run("ast");
        let vm = run("vm");
        assert!(ast.status.success(), "{name}: {}", stderr(&ast));
        assert_eq!(ast.status.code(), vm.status.code(), "{name}");
        assert_eq!(stdout(&ast), stdout(&vm), "{name}");
        assert_eq!(stderr(&ast), stderr(&vm), "{name}");
    }
}

#[test]
fn local_module_binary_analysis_and_hunt() {
    let s = Sandbox::new();
    s.bytes("header.bin", b"GAK\0GA");
    s.write(
        "helper.gak",
        "import std.binary as binary\nfn signature(source) = binary.deep(source, 0, \"u16le\")\n",
    );
    let script = s.write("main.gak", "requires { file.read }\nimport std.binary as binary\nimport \"helper.gak\" as helper\nlet source = binary.analyze(\"header.bin\", 100)\nlet sig = helper.signature(source)\nimpact sig\nprint binary.hunt(source, \"hex:4741\")\n");
    let out = s.run(&script, true);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("decoder: u16le, value: 16711"));
    assert!(stdout(&out).contains("[0, 4]"));
}

#[test]
fn script_declaration_and_cli_permission_are_both_required() {
    let s = Sandbox::new();
    s.bytes("file.bin", b"GAK");
    let without_decl = s.write(
        "no-decl.gak",
        "import std.binary as b\nprint b.analyze(\"file.bin\", 10)\n",
    );
    let out = s.run(&without_decl, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("was not declared with requires"));
    let without_cli = s.write(
        "no-cli.gak",
        "requires { file.read }\nimport std.binary as b\nprint b.analyze(\"file.bin\", 10)\n",
    );
    let out = s.run(&without_cli, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not allowed"));
}

#[test]
fn bounds_and_snapshot_limit_fail_explicitly() {
    let s = Sandbox::new();
    s.bytes("tiny.bin", b"GA");
    let bounds = s.write("bounds.gak", "requires { file.read }\nimport std.binary as b\nlet s = b.analyze(\"tiny.bin\", 10)\nimpact b.deep(s, 1, \"u16le\")\n");
    let out = s.run(&bounds, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("out of bounds"));
    let limit = s.write(
        "limit.gak",
        "requires { file.read }\nimport std.binary as b\nprint b.analyze(\"tiny.bin\", 1)\n",
    );
    let out = s.run(&limit, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("LimitExceeded"));
}

#[test]
fn arithmetic_checks_overflow_and_zero_division() {
    let s = Sandbox::new();
    let overflow = s.write("overflow.gak", "print 9223372036854775807 + 1\n");
    let out = s.run(&overflow, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("integer overflow"));
    let zero = s.write("zero.gak", "print 4 / 0\n");
    let out = s.run(&zero, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("division by zero"));
}

#[test]
fn multiline_if_expression_runs_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "multiline-if.gak",
        "print if true {\n    42\n} else {\n    0\n}\n",
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "42\n");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\n");
}

#[test]
fn imported_module_effects_need_local_declaration_and_root_grant() {
    let s = Sandbox::new();
    s.bytes("file.bin", b"GAK");
    s.write(
        "hidden.gak",
        "import std.binary as b\nfn sneak() = b.analyze(\"file.bin\", 10)\n",
    );
    let main = s.write(
        "main.gak",
        "requires { file.read }\nimport \"hidden.gak\" as hidden\nprint hidden.sneak()\n",
    );
    let out = s.run(&main, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("was not declared with requires in"));
    s.write(
        "hidden.gak",
        "requires { file.read }\nimport std.binary as b\nfn sneak() -> Source = b.analyze(\"file.bin\", 10)\n",
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&main, engine, true, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).contains("sha256:"));
    }
    let no_grant = s.write("no-grant.gak", "import hidden\nprint hidden.sneak()\n");
    let out = s.run(&no_grant, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("root script does not grant it"));
    s.write("noisy.gak", "print 1\n");
    let main = s.write("noisy-main.gak", "import \"noisy.gak\" as noisy\nprint 2\n");
    let out = s.run(&main, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot execute top-level actions"));
}

#[test]
fn imports_are_confined_and_cycles_are_rejected() {
    let s = Sandbox::new();
    s.write("outside.gak", "fn f() = 1\n");
    let main = s.write(
        "project/main.gak",
        "import \"../outside.gak\" as outside\nprint 1\n",
    );
    let out = s.run(&main, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("outside project"));
    s.write("a.gak", "import \"b.gak\" as b\nprint 1\n");
    s.write("b.gak", "import \"a.gak\" as a\n");
    let out = s.run(&s.dir.join("a.gak"), false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cyclic import"));
}

#[test]
fn parser_reports_source_position() {
    let s = Sandbox::new();
    let script = s.write("bad.gak", "print (1 + 2\n");
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("bad.gak:2:1:"), "{}", stderr(&out));
}

#[test]
fn source_hash_matches_sha256_test_vector() {
    let s = Sandbox::new();
    s.bytes("abc.bin", b"abc");
    let script = s.write("hash.gak", "requires { file.read }\nimport std.binary as b\nlet source = b.analyze(\"abc.bin\", 3)\nprint b.sha256(source)\n");
    let out = s.run(&script, true);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hunt_reports_overlapping_matches() {
    let s = Sandbox::new();
    s.bytes("run.bin", b"AAAA");
    let script = s.write("hunt.gak", "requires { file.read }\nimport std.binary as b\nlet source = b.analyze(\"run.bin\", 4)\nprint b.hunt(source, \"AA\")\n");
    let out = s.run(&script, true);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "[0, 1, 2]");
}

#[test]
fn masked_hex_hunt_matches_nibbles_and_overlaps_in_both_engines_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "hunt_masked.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"a1 b2 a3 b4 a1 b2\"))\nprint binary.hunt(source, \"hex:a? b?\")\nprint binary.hunt(source, \"hex:?? b?\")\nprint binary.hunt(source, \"hex:a1 b2\")\n",
    );
    let expected = "[0, 2, 4]\n[0, 2, 4]\n[0, 4]\n";
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), expected);
}

#[test]
fn masked_hex_hunt_rejects_malformed_or_oversized_patterns() {
    let s = Sandbox::new();
    for (name, pattern, message) in [
        ("odd", "hex:a? ?", "even number of nibbles"),
        ("invalid", "hex:gg", "invalid hex pattern"),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!("import std.binary\nlet source = binary.snapshot(binary.from_hex(\"a1 b2\"))\nprint binary.hunt(source, \"{pattern}\")\n"),
        );
        let result = s.run(&script, false);
        assert!(!result.status.success());
        assert!(stderr(&result).contains(message), "{}", stderr(&result));
    }
    let long = format!("hex:{}", "??".repeat(65));
    let script = s.write(
        "long.gak",
        &format!("import std.binary\nlet source = binary.snapshot(binary.from_hex(\"a1 b2\"))\nprint binary.hunt(source, \"{long}\")\n"),
    );
    let result = s.run(&script, false);
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("masked hex pattern exceeds 64 bytes"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn hexdump_is_bounded_and_uses_source_relative_offsets_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write("hex_view.gak", include_str!("../examples/hex_view.gak"));
    let mut expected = None;
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        let output = stdout(&result);
        let rows = output.lines().collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].starts_with("00000000  47 41 4b 00 41 42 43 7f "));
        assert!(rows[0].ends_with("|GAK.ABC.|"));
        assert!(rows[1].starts_with("00000003  00 41 42 43 "));
        assert!(rows[1].ends_with("|.ABC|"));
        assert!(rows[2].starts_with("00000000  41 42 43 "));
        assert!(rows[2].ends_with("|ABC|"));
        if let Some(previous) = &expected {
            assert_eq!(&output, previous);
        }
        expected = Some(output);
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    let bundle = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundle.status.success(), "{}", stderr(&bundle));
    assert_eq!(Some(stdout(&bundle)), expected);

    for (name, call, message) in [
        (
            "negative",
            "binary.hexdump(source, -1, 1)",
            "offset must not be negative",
        ),
        ("outside", "binary.hexdump(source, 7, 2)", "out of bounds"),
        (
            "arity",
            "binary.hexdump(source, 1)",
            "expects 1 or 3 arguments",
        ),
        ("type", "binary.hexdump(1)", "expected Source"),
    ] {
        let invalid = s.write(
            &format!("hex-{name}.gak"),
            &format!("import std.binary\nlet source = binary.snapshot(binary.from_hex(\"47 41 4b 00 41 42 43 7f\"))\nprint {call}\n"),
        );
        let result = s.run(&invalid, false);
        assert!(!result.status.success());
        assert!(stderr(&result).contains(message), "{}", stderr(&result));
    }
    let oversized = s.write(
        "hex-oversized.gak",
        "import std.binary\nimport std.bytes\nlet source = binary.snapshot(bytes.repeat(bytes.from_hex(\"41\"), 4097))\nprint binary.hexdump(source, 0, 4097)\n",
    );
    let result = s.run(&oversized, false);
    assert!(!result.status.success());
    assert!(stderr(&result).contains("hexdump length exceeds 4096 bytes"));

    let default = s.write(
        "hex-default.gak",
        "import std.binary\nimport std.bytes\nlet source = binary.snapshot(bytes.repeat(bytes.from_hex(\"41\"), 257))\nprint binary.hexdump(source)\n",
    );
    let result = s.run(&default, false);
    assert!(result.status.success(), "{}", stderr(&result));
    let output = stdout(&result);
    assert_eq!(output.lines().count(), 16);
    assert!(output.lines().last().unwrap().starts_with("000000f0  "));
}

#[test]
fn strings_find_ascii_and_utf16le_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "strings.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00 47 41 4b 00 61 62 63 20 31 ff 58 00 59 00 00\"))\nlet view = binary.view(source, 5, 5)\nprint binary.strings(source, 3, \"ascii\")\nprint binary.strings(source, 2, \"utf16le\")\nprint binary.read_text(source, 1, 3, \"ascii\")\nprint binary.read_text(source, 5, 5, \"ascii\")\nprint binary.read_text(source, 11, 2, \"utf16le\")\nprint binary.strings(view, 3, \"ascii\")\n",
    );
    let expected = "[1, 5]\n[11]\nGAK\nabc 1\nXY\n[0]\n";
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), expected);
}

#[test]
fn strings_validate_encoding_ranges_and_read_limit() {
    let s = Sandbox::new();
    for (name, call, message) in [
        (
            "bad-encoding",
            "binary.strings(source, 1, \"utf8\")",
            "text encoding must be ascii or utf16le",
        ),
        (
            "bad-minimum",
            "binary.strings(source, 0, \"ascii\")",
            "minimum string length must be",
        ),
        (
            "too-short",
            "binary.read_text(source, 0, 1, \"ascii\")",
            "LimitExceeded",
        ),
        (
            "bad-offset",
            "binary.read_text(source, 3, 2, \"ascii\")",
            "text offset out of bounds",
        ),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!("import std.binary\nlet source = binary.snapshot(binary.from_hex(\"47 41 4b\"))\nprint {call}\n"),
        );
        let result = s.run(&script, false);
        assert!(!result.status.success());
        assert!(stderr(&result).contains(message), "{}", stderr(&result));
    }
}

#[test]
fn entropy_is_a_traceable_observation_in_ast_vm_bundle_and_audit() {
    let s = Sandbox::new();
    let script = s.write(
        "entropy.gak",
        "import std.binary\nimport std.audit\nlet source = binary.snapshot(binary.from_hex(\"00 01 00 01\"))\nlet view = binary.view(source, 1, 2)\nlet measure = binary.entropy(view)\nprint binary.value(measure)\nprint binary.width(measure)\nimpact measure\nimpact audit.bound(measure, 900, 1100, \"entropy.expected\")\nprint binary.value(binary.entropy(binary.snapshot(binary.from_hex(\"\"))))\n",
    );
    let mut expected = None;
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        let output = stdout(&result);
        assert!(output.starts_with("1000\n2\n"), "{output}");
        assert!(output.contains("decoder: entropy_milli"), "{output}");
        assert!(output.contains("view of sha256:"), "{output}");
        assert!(
            output.contains("rule: \"entropy.expected\", status: pass"),
            "{output}"
        );
        assert!(output.ends_with("0\n"), "{output}");
        if let Some(previous) = &expected {
            assert_eq!(&output, previous);
        }
        expected = Some(output);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), expected.unwrap());
}

#[test]
fn formats_probe_reports_native_executable_with_snapshot_id() {
    let s = Sandbox::new();
    let executable = s.dir.join("sample.bin");
    fs::copy(env!("CARGO_BIN_EXE_galeikan"), &executable).unwrap();
    let size = fs::metadata(&executable).unwrap().len();
    let script = s.write(
        "probe.gak",
        &format!(
            "requires {{ file.read }}\nimport std.binary as binary\nimport std.formats as formats\nlet source = binary.analyze(\"sample.bin\", {size})\nlet report = formats.probe(source)\nimpact report\nimpact formats.field(report, \"entry\")\n"
        ),
    );
    let out = s.run(&script, true);
    assert!(out.status.success(), "{}", stderr(&out));
    let result = stdout(&out);
    assert!(result.contains("sha256:"), "{result}");
    assert!(result.contains("header=[0.."), "{result}");
    assert!(result.contains("range: ["), "{result}");
    assert!(result.contains("value:"), "{result}");
    assert!(
        result.contains(if cfg!(windows) { "PE32+" } else { "ELF64" }),
        "{result}"
    );
}

#[test]
fn gak_and_gaks_share_import_runtime_bundle_and_case_semantics() {
    let s = Sandbox::new();
    s.write("helper.gaks", "fn twice(value: i64) -> i64 = value * 2\n");
    let script = s.write(
        "main.gaks",
        "requires { case.write }\nfrom helper import twice\nprint twice(21)\n",
    );
    for engine in ["ast", "vm"] {
        let case = s.dir.join(format!("source-{engine}.json"));
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--case"])
            .arg(&case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "42\n");
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("helper.gaks")).unwrap();
    let case = s.dir.join("bundle.json");
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "42\n");
    let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("verify-case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", stderr(&verified));

    s.write("helper.gak", "fn twice(value: i64) -> i64 = value * 3\n");
    s.write("helper.gaks", "fn twice(value: i64) -> i64 = value * 2\n");
    let ambiguous = s.write("ambiguous.gak", "import helper\nprint helper.twice(21)\n");
    let output = s.run(&ambiguous, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("ambiguous Galeikan module helper"));
}

#[test]
fn imports_without_alias_and_script_arguments() {
    let s = Sandbox::new();
    s.write("helper.gak", "fn label(value) = value\n");
    let script = s.write(
        "main.gak",
        "import std.cli\nimport helper\nprint cli.count()\nprint helper.label(cli.arg(0))\n",
    );
    let out = s.run_args(&script, false, &["sample.bin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "1\nsample.bin\n");
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("argument index out of range"));

    s.write("tools/math.gak", "fn twice(n) = n * 2\n");
    let nested = s.write("nested.gak", "import tools.math\nprint math.twice(21)\n");
    let out = s.run(&nested, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\n");

    let numeric = s.write("numeric.gak", "import std.cli\nprint cli.int(0) + 2\n");
    let out = s.run_args(&numeric, false, &["40"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\n");
    let out = s.run_args(&numeric, false, &["not-a-number"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("argument 0 is not an i64"));
}

#[test]
fn from_imports_work_in_ast_vm_bundle_and_reject_name_collisions() {
    let s = Sandbox::new();
    s.write("math.gak", "fn twice(n: i64) -> i64 = n * 2\n");
    let script = s.write(
        "from_import.gak",
        "from std.binary import (\n    from_hex,\n    snapshot as snap,\n    size,\n)\nfrom math import twice as double\nfn result() -> i64 = double(size(snap(from_hex(\"4d 5a\"))))\nprint result()\n",
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{engine}: {}", stderr(&out));
        assert_eq!(stdout(&out), "4\n");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("math.gak")).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), "4\n");

    s.write("math.gak", "fn twice(n: i64) -> i64 = n * 2\n");
    let duplicate = s.write(
        "duplicate.gak",
        "from math import twice\nfn twice(n: i64) -> i64 = n\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&duplicate)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("imported name twice conflicts with another binding"));

    let empty = s.write("empty_import.gak", "from math import ()\nprint 1\n");
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&empty)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("import group cannot be empty"));
}

#[test]
fn from_imports_validate_static_exports_when_unused() {
    let s = Sandbox::new();
    s.write("helper.gak", "fn valid() -> i64 = 42\nlet constant = 1\n");
    for (name, source, missing) in [
        ("local", "from helper import absent\nprint 1\n", "absent"),
        (
            "standard",
            "from std.binary import absent\nprint 1\n",
            "absent",
        ),
    ] {
        let script = s.write(&format!("{name}.gak"), source);
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name}");
        assert!(
            stderr(&output).contains(&format!("unknown imported symbol {missing}")),
            "{name}: {}",
            stderr(&output)
        );
    }
    s.write(
        "galeikan.json",
        "{\"version\":1,\"dependencies\":{\"utils\":\"vendor/utils\"}}\n",
    );
    s.write("vendor/utils/main.gak", "fn valid() -> i64 = 42\n");
    let lock = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("lock")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(lock.status.success(), "{}", stderr(&lock));
    let package = s.write("pkg.gak", "from pkg.utils import absent\nprint 1\n");
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&package)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown imported symbol absent from pkg.utils"));
}

#[test]
fn from_import_can_bind_module_values_across_engines_and_bundle() {
    let s = Sandbox::new();
    s.write(
        "config.gak",
        "let base: i64 = 40\nlet label: str = \"research\"\n",
    );
    let script = s.write(
        "main.gak",
        "from config import base as start, label\nfn answer() -> i64 = start + 2\nprint answer()\nprint label\n",
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{engine}: {}", stderr(&out));
        assert_eq!(stdout(&out), "42\nresearch\n");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("config.gak")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\nresearch\n");
}

#[test]
fn from_import_rejects_shadowed_names_before_execution() {
    let s = Sandbox::new();
    s.write("config.gak", "let base = 40\n");
    for source in [
        "from config import base\nfn f(base: i64) -> i64 = base\n",
        "from config import base\nfn f() -> i64 {\n    let base = 1\n    return base\n}\n",
        "from config import base\nfor base in 1 {\n    print base\n}\n",
    ] {
        let script = s.write("shadow.gak", source);
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(stderr(&out).contains("imported name base conflicts"));
    }
}

#[test]
fn multiline_declarations_and_python_import_run_in_ast_vm_and_bundle() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.gak", "fn adjust(value: i64) -> i64 = value + 2\n");
    s.write("py_helper.py", "def double(value):\n    return value * 2\n");
    let script = s.write(
        "main.gak",
        "requires {\n    python.exec,\n}\nimport helper\nfrom py.py_helper import double as python_double\nfn report(\n    value: i64,\n) -> i64 {\n    return python_double(helper.adjust(value))\n}\nprint report(20)\n",
    );
    for engine in ["ast", "vm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-python", python])
            .output()
            .unwrap();
        assert!(out.status.success(), "{engine}: {}", stderr(&out));
        assert_eq!(stdout(&out), "44\n");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("helper.gak")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .args(["--allow-python", python])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "44\n");
}

#[test]
fn python_module_calls_require_declaration_and_cli_permission() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "helper.py",
        "def shout(text):\n    return text.upper() + '!'\n\ndef add(left, right):\n    return left + right\n",
    );
    let script = s.write(
        "main.gak",
        "requires { python.exec }\nfrom py.helper import (\n    shout,\n    add as plus,\n)\nprint shout(\"galeikan\")\nprint plus(20, 22)\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "GALEIKAN!\n42\n");

    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), vm.status.code());
    assert_eq!(stdout(&out), stdout(&vm));

    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--allow-python"));

    let missing_effect = s.write("missing.gak", "import py.helper\nprint helper.add(1, 2)\n");
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&missing_effect)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("python.exec was not declared"));

    s.write("outside.py", "def value():\n    return 7\n");
    let confined = s.write(
        "project/confined.gak",
        "requires { python.exec }\nimport \"py:../outside.py\" as outside\nprint outside.value()\n",
    );
    let out = s.run(&confined, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Python import outside project"));

    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&compiled), stdout(&vm));
}

#[test]
fn python_module_state_persists_within_ast_vm_and_bundle_runs() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write("state.py", "import os\ncounter = 0\ndef bump():\n    global counter\n    counter += 1\n    return counter\ndef fail():\n    raise ValueError('boom')\ndef crash():\n    os._exit(3)\n");
    let script = s.write(
        "state.gak",
        "requires { python.exec }\nimport py.state\nfrom std.result import message, is_error\nfn checked() -> Result<i64> = state.fail()\nfn crashed() -> Result<i64> = state.crash()\nprint state.bump()\nprint state.bump()\nprint state.counter\nprint message(checked())\nprint state.bump()\nprint is_error(crashed())\nprint state.bump()\n",
    );
    for engine in ["ast", "vm"] {
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .arg("--engine")
            .arg(engine)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        let text = stdout(&output);
        assert!(text.starts_with("1\n2\n2\n"), "{engine}: {text}");
        assert!(text.contains("ValueError: boom"), "{engine}: {text}");
        assert!(text.ends_with("3\ntrue\n1\n"), "{engine}: {text}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with("1\n2\n2\n"), "{text}");
    assert!(text.contains("ValueError: boom"), "{text}");
    assert!(text.ends_with("3\ntrue\n1\n"), "{text}");
}

#[test]
fn python_values_are_available_with_module_and_from_import_syntax() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write(
        "settings.py",
        "threshold = 40\nlabel = 'research'\nflag = True\npayload = b'MZ'\n",
    );
    let script = s.write(
        "main.gak",
        "requires { python.exec }\nfrom py.settings import threshold as start, label, flag\nimport py.settings as settings\nlet answer: i64 = start + 2\nprint answer\nprint label\nprint flag\nprint settings.payload\n",
    );
    for engine in ["ast", "vm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .arg("--engine")
            .arg(engine)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(out.status.success(), "{engine}: {}", stderr(&out));
        assert_eq!(
            stdout(&out),
            "42\nresearch\ntrue\nbytes(2 bytes, hex:4d5a)\n"
        );
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(
        stdout(&bundled),
        "42\nresearch\ntrue\nbytes(2 bytes, hex:4d5a)\n"
    );
    let no_effect = s.write(
        "no_effect.gak",
        "from py.settings import threshold\nprint threshold\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&no_effect)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("python.exec was not declared"));
}

#[test]
fn python_bridge_round_trips_bytes_and_booleans_in_source_and_bundle() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let s = Sandbox::new();
    s.write("helper.py", "def flip(data):\n    return data[::-1]\n\ndef is_magic(data):\n    return data.startswith(b'GAK')\n\ndef negate(flag):\n    return not flag\n\ndef too_large():\n    return bytes(500001)\n");
    let script = s.write("main.gak", "requires { python.exec }\nimport std.binary\nimport py.helper\nlet source = binary.snapshot(binary.from_hex(\"47 41 4b 00\"))\nlet raw = binary.extract(source, 0, binary.size(source))\nlet flipped = helper.flip(raw)\nprint binary.size(flipped)\nprint helper.is_magic(raw)\nprint helper.negate(false)\nimpact binary.deep(binary.snapshot(flipped), 0, \"u16le\")\n");
    let source = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(source.status.success(), "{}", stderr(&source));
    assert!(stdout(&source).starts_with("4\ntrue\ntrue\n"));
    assert!(stdout(&source).contains("decoder: u16le, value: 19200"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&source), stdout(&compiled));

    let oversized = s.write(
        "oversized.gak",
        "requires { python.exec }\nimport py.helper\nprint helper.too_large()\n",
    );
    let invalid = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&oversized)
        .arg("--allow-python")
        .arg(python)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(
        stderr(&invalid).contains("exceeds 500000 bytes"),
        "{}",
        stderr(&invalid)
    );
}

#[test]
fn block_functions_have_local_bindings_and_return_on_every_path() {
    let s = Sandbox::new();
    let script = s.write(
        "blocks.gak",
        "fn square_plus_one(n) {\n    let square = n * n\n    return square + 1\n}\nprint square_plus_one(4)\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "17\n");

    let bad = s.write(
        "missing-return.gak",
        "fn bad(n) {\n    let x = n\n}\nprint bad(1)\n",
    );
    let out = s.run(&bad, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("function block needs a return on every path"));
}

#[test]
fn comparisons_and_if_expressions_are_typed_and_lazy() {
    let s = Sandbox::new();
    let script = s.write(
        "decision.gak",
        "fn classify(n) {\n    return if n * 2 >= 10 { \"large\" } else { \"small\" }\n}\nprint classify(5)\nprint classify(4)\nprint 2 + 3 * 4 == 14\nprint if true { 42 } else { 1 / 0 }\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "large\nsmall\ntrue\n42\n");

    let bad = s.write("not-bool.gak", "print if 1 { 2 } else { 3 }\n");
    let out = s.run(&bad, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected bool, got i64"));

    let reserved = s.write("reserved.gak", "let if = 1\nprint if\n");
    let out = s.run(&reserved, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reserved binding name"));
}

#[test]
fn else_if_chain_matches_ast_vm_and_bundle_without_changing_precedence() {
    let s = Sandbox::new();
    let script = s.write(
        "decision_chain.gak",
        include_str!("../examples/decision_chain.gak"),
    );
    let expected = "critical\nhigh\nmedium\nlow\n11\n7\n";
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), expected, "{engine}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), expected);

    let missing_else = s.write(
        "missing_else.gak",
        "print if true { 1 } else if false { 2 }\n",
    );
    let output = s.run(&missing_else, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("expected Ident(\"else\")"));

    let deeply_nested = s.write(
        "deep_else_if.gak",
        &format!("print {}{{ 1 }}\n", "if false { 0 } else ".repeat(130)),
    );
    let output = s.run(&deeply_nested, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("expression nesting too deep"));
}

#[test]
fn conditional_action_blocks_match_ast_vm_and_bundle_with_scoped_bindings() {
    let s = Sandbox::new();
    let script = s.write(
        "conditional_actions.gak",
        include_str!("../examples/conditional_actions.gak"),
    );
    let expected = "high\n1\n1\n0\n";
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), expected, "{engine}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), expected);

    let leaked = s.write(
        "leaked.gak",
        "if true {\n    let hidden = 3\n}\nprint hidden\n",
    );
    let output = s.run(&leaked, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown name hidden"));

    let invalid_else = s.write(
        "invalid_else.gak",
        "if true {\n    print 1\n} else {\n    print missing\n}\n",
    );
    let output = s.run(&invalid_else, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown name missing"));

    let invalid_condition = s.write("condition.gak", "if 1 {\n    print 1\n}\n");
    let output = s.run(&invalid_condition, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("if condition: expected bool"));

    let binary_branch = s.write(
        "binary_branch.gak",
        "from std.binary import from_hex, snapshot, deep, value\nif true {\n    let source = snapshot(from_hex(\"41 42\"))\n    if true {\n        print value(deep(source, 0, \"u8\"))\n    }\n}\n",
    );
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&binary_branch, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), "65\n");
    }

    let next_line_else = s.write(
        "next_line_else.gak",
        "if false {\n    print 1\n}\nelse {\n    print 2\n}\nif false {\n    print 3\n}\nprint 4\n",
    );
    let output = s.run(&next_line_else, false);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "2\n4\n");

    s.write("action_module.gak", "if true {\n    print 1\n}\n");
    let import_action = s.write("import_action.gak", "import action_module\nprint 2\n");
    let output = s.run(&import_action, false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("imported module cannot execute top-level actions"));
}

#[test]
fn early_returns_leave_nested_blocks_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "early_return.gak",
        include_str!("../examples/early_return.gak"),
    );
    let expected = "critical\nreview\nlow\n3\n2\n0\n";
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), expected, "{engine}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), expected);

    let outside = s.write("outside.gak", "if true {\n    return 1\n}\nprint 2\n");
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&outside)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("return outside function"));

    let incompatible = s.write(
        "incompatible.gak",
        "fn choose(value: bool) -> i64 {\n    if value {\n        return \"wrong\"\n    }\n    return 1\n}\nprint choose(false)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&incompatible)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("early return has str, expected i64"));
}

#[test]
fn early_return_can_propagate_result_from_direct_import() {
    let s = Sandbox::new();
    let script = s.write(
        "result_guard.gak",
        "from std.result import fail, is_error\nfn guard(value: i64) -> Result<i64> {\n    if value < 0 {\n        return fail(\"negative\")\n    }\n    return value\n}\nprint is_error(guard(-1))\nprint guard(5)?\n",
    );
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), "true\n5\n");
    }
}

#[test]
fn exhaustive_return_blocks_need_no_fallback_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "exhaustive_return.gak",
        include_str!("../examples/exhaustive_return.gak"),
    );
    let expected = "critical\nreview\nlow\n3\n-1\n0\n";
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), expected, "{engine}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), expected);

    let missing_else = s.write(
        "missing_else.gak",
        "fn choose(flag: bool) -> i64 {\n    if flag {\n        return 1\n    }\n}\nprint choose(true)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&missing_else)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("function block needs a return on every path"));

    let loop_only = s.write(
        "loop_only.gak",
        "fn choose() -> i64 {\n    while true {\n        return 1\n    }\n}\nprint choose()\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&loop_only)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("function block needs a return on every path"));

    let mismatch = s.write(
        "mismatch.gak",
        "fn choose(flag: bool) {\n    if flag {\n        return 1\n    } else {\n        return \"wrong\"\n    }\n}\nprint choose(true)\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&mismatch)
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("early return has str, expected i64"));
}

#[test]
fn boolean_operators_have_precedence_and_short_circuit_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "logic.gak",
        "fn dynamic() = 1\nprint false and 1 / 0 == 0\nprint true or 1 / 0 == 0\nprint true or false and false\nprint not 1 == 1\nprint not false and 2 < 3\nprint false and dynamic()\nprint if true and not false { \"yes\" } else { \"no\" }\n",
    );
    let expected = "false\ntrue\ntrue\nfalse\ntrue\nfalse\nyes\n";
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), expected);
}

#[test]
fn boolean_operators_require_bool_even_on_skipped_branches() {
    let s = Sandbox::new();
    for (name, source) in [
        ("bad-and", "print false and 1\n"),
        ("bad-or", "print true or 1\n"),
        ("bad-not", "print not 1\n"),
    ] {
        let script = s.write(&format!("{name}.gak"), source);
        let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("check")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            stderr(&result).contains("expected bool, got i64"),
            "{}",
            stderr(&result)
        );
    }
    let dynamic = s.write("dynamic.gak", "fn number() = 1\nprint true and number()\n");
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&dynamic, engine, false, &[]);
        assert!(!result.status.success());
        assert!(
            stderr(&result).contains("boolean expected"),
            "{}",
            stderr(&result)
        );
    }
    let reserved = s.write("reserved.gak", "let and = true\n");
    let result = s.run(&reserved, false);
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("reserved binding name"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn while_rechecks_mutable_condition_in_root_function_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write(
        "while.gak",
        "import std.binary\nvar total = 0\nfn triangular(limit: i64) -> i64 {\n    var index = 0\n    var sum = 0\n    while index < limit {\n        sum = sum + index\n        index = index + 1\n    }\n    return sum\n}\nfor byte in binary.from_hex(\"01 02\") {\n    var index = 0\n    while index < byte {\n        total = total + 1\n        index = index + 1\n    }\n}\nprint total\nprint triangular(4)\n",
    );
    let expected = "3\n6\n";
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&script, engine, false, &[]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(stdout(&result), expected);
}

#[test]
fn while_requires_bool_and_obeys_action_limit() {
    let s = Sandbox::new();
    let bad = s.write("bad-while.gak", "while 1 {\n    print 2\n}\n");
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("while condition: expected bool, got i64"),
        "{}",
        stderr(&result)
    );

    let dynamic = s.write(
        "dynamic-while.gak",
        "fn number() = 1\nwhile number() {\n}\n",
    );
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&dynamic, engine, false, &[]);
        assert!(!result.status.success());
        assert!(
            stderr(&result).contains("boolean expected"),
            "{}",
            stderr(&result)
        );
    }

    let unbounded = s.write("unbounded-while.gak", "while true {\n}\n");
    let result = s.run_engine(&unbounded, "vm", false, &[]);
    assert!(!result.status.success());
    assert!(
        stderr(&result).contains("execution exceeds 1000000 action steps"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn typed_functions_check_module_calls_before_effects_run() {
    let s = Sandbox::new();
    s.write(
        "helper.gak",
        "import std.binary\nfn signature(source: Source) -> Observation = binary.deep(source, 0, \"u8\")\n",
    );
    let script = s.write(
        "typed.gak",
        "requires { file.read }\nimport std.binary\nimport helper\nlet source = binary.analyze(\"missing.bin\", 16)\nimpact helper.signature(source)\nprint 1 + true\n",
    );
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("expected i64, got bool"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("file access not allowed"));

    let script = s.write(
        "wrong-argument.gak",
        "import helper\nprint helper.signature(42)\n",
    );
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("expected Source, got i64"),
        "{}",
        stderr(&out)
    );

    let script = s.write(
        "wrong-return.gak",
        "fn bad(x: i64) -> bool = x + 1\nprint bad(1)\n",
    );
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("returns i64, expected bool"),
        "{}",
        stderr(&out)
    );

    let script = s.write(
        "valid.gak",
        "fn double(x: i64) -> i64 = x * 2\nprint double(21)\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\n");
}

#[test]
fn check_command_validates_without_running_effects() {
    let s = Sandbox::new();
    let valid = s.write(
        "check-valid.gak",
        "requires { file.read }\nimport std.binary\nlet source = binary.analyze(\"missing.bin\", 16)\nprint binary.size(source)\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&valid)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());

    let invalid = s.write("check-invalid.gak", "print 1 + true\n");
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&invalid)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected i64, got bool"));
}

#[test]
fn result_functions_capture_errors_and_question_mark_propagates() {
    let s = Sandbox::new();
    s.bytes("sample.bin", b"GA");
    let script = s.write(
        "result.gak",
        "requires { file.read }\nimport std.binary\nfn read(path: str) -> Result<Source> = binary.analyze(path, 16)\nfn inspect(path: str) -> Result<Observation> {\n    let source = read(path)?\n    return binary.deep(source, 0, \"u16le\")\n}\nprint inspect(\"missing.bin\")\nimpact inspect(\"sample.bin\")?\n",
    );
    let out = s.run(&script, true);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("error("));
    assert!(stdout(&out).contains("missing.bin"));
    assert!(stdout(&out).contains("impact {"));

    let unhandled = s.write(
        "unhandled.gak",
        "requires { file.read }\nimport std.binary\nfn read(path: str) -> Result<Source> = binary.analyze(path, 16)\nprint read(\"missing.bin\")?\n",
    );
    let out = s.run(&unhandled, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("missing.bin"));

    let wrong_return = s.write(
        "wrong-result.gak",
        "fn bad() -> Result<i64> = \"wrong\"\nprint bad()\n",
    );
    let out = s.run(&wrong_return, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("returns str, expected Result<i64>"));

    let wrong_try = s.write("wrong-try.gak", "print 42?\n");
    let out = s.run(&wrong_try, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("? expects Result<T>, got i64"));

    let forwarded = s.write(
        "forwarded.gak",
        "import std.result\nfn answer() -> Result<i64> = 42\nfn fail() -> Result<i64> = 1 / 0\nfn forward(value: Result<i64>) -> Result<i64> = value\nprint forward(answer())?\nprint result.is_error(fail())\nprint result.recover(fail(), 7)\nprint result.recover(answer(), 7)\n",
    );
    let out = s.run(&forwarded, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "42\ntrue\n7\n42\n");

    let wrong_fallback = s.write(
        "wrong-fallback.gak",
        "import std.result\nfn answer() -> Result<i64> = 42\nprint result.recover(answer(), \"no\")\n",
    );
    let out = s.run(&wrong_fallback, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected i64, got str"));
}

#[test]
fn explicit_results_work_across_modules_engines_and_bundle() {
    let s = Sandbox::new();
    s.write(
        "checks.gak",
        "from std.result import ok, fail\nfn gate(value: i64) -> Result<i64> = if value < 2 { fail(\"too small\") } else { ok(value) }\n",
    );
    let script = s.write(
        "results.gak",
        "import checks\nfrom std.result import ok, fail, is_ok, is_error, message, recover\nfn forward(value: i64) -> Result<i64> {\n    let checked: i64 = checks.gate(value)?\n    return ok(checked + 1)\n}\nlet good: Result<i64> = checks.gate(3)\nlet bad: Result<i64> = checks.gate(1)\nprint is_ok(good)\nprint good?\nprint is_error(bad)\nprint message(bad)\nprint recover(bad, 7)\nprint recover(fail(\"fallback\"), 9)\nprint forward(3)?\nprint message(forward(0))\n",
    );
    let mut expected = None;
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        let output = stdout(&out);
        assert!(output.starts_with("true\n3\ntrue\ntoo small\n7\n9\n4\n"));
        assert!(output.contains("results.gak:4:5: too small"));
        if let Some(previous) = &expected {
            assert_eq!(&output, previous);
        }
        expected = Some(output);
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(s.dir.join("checks.gak")).unwrap();
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), expected.unwrap());
}

#[test]
fn explicit_result_constructors_reject_invalid_types_and_messages() {
    let s = Sandbox::new();
    for (name, script, expected) in [
        (
            "wrong-fail-type",
            "import std.result\nprint result.fail(42)\n",
            "expected str, got i64",
        ),
        (
            "nested-result",
            "import std.result\nprint result.ok(result.ok(42))\n",
            "cannot wrap Result<i64>",
        ),
        (
            "list-result",
            "import std.result\nprint result.ok([1])\n",
            "cannot wrap List<i64>",
        ),
        (
            "empty-error",
            "import std.result\nprint result.fail(\"\")\n",
            "nonempty message",
        ),
        (
            "message-on-success",
            "import std.result\nprint result.message(result.ok(42))\n",
            "requires a failed Result",
        ),
    ] {
        let path = s.write(&format!("{name}.gak"), script);
        let out = s.run(&path, false);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(expected), "{}", stderr(&out));
    }
}

#[test]
fn bounded_tcp_response_can_be_analyzed_as_binary_source() {
    let s = Sandbox::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "tcp.gak",
        &format!(
            "requires {{ net.connect }}\nimport std.net\nimport std.binary\nlet request = binary.from_hex(\"50 49 4e 47 00\")\nlet source = net.exchange(\"127.0.0.1\", {port}, request, 4, 2000)\nimpact binary.deep(source, 0, \"u16le\")\nprint binary.hunt(source, binary.from_hex(\"47 41\"))\n"
        ),
    );
    let out = s.run(&script, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("network access not allowed"));

    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut client, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            client.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"PING\0");
            client.write_all(b"GAK\0").unwrap();
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--engine")
        .arg("vm")
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let output = stdout(&out);
    assert!(output.contains("sha256:"), "{output}");
    assert!(
        output.contains(&format!("peer 127.0.0.1:{port}")),
        "{output}"
    );
    assert!(output.contains("decoder: u16le, value: 16711"), "{output}");
    assert!(output.ends_with("[0]\n"), "{output}");
    assert!(vm.status.success(), "{}", stderr(&vm));
    let vm_output = stdout(&vm);
    assert!(
        vm_output.contains("decoder: u16le, value: 16711"),
        "{vm_output}"
    );
    assert!(vm_output.ends_with("[0]\n"), "{vm_output}");

    let missing_effect = s.write(
        "missing-net.gak",
        &format!("import std.net\nprint net.exchange(\"127.0.0.1\", {port}, \"PING\", 4, 2000)\n"),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&missing_effect)
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("net.connect was not declared"));
}

#[test]
fn bounded_udp_datagram_works_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "udp.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import datagram\nimport std.binary\nlet request = binary.from_hex(\"50 49 4e 47 00\")\nlet source = datagram(\"127.0.0.1\", {port}, request, 4, 2000)\nimpact binary.deep(source, 0, \"u16le\")\nprint binary.size(source)\n"
        ),
    );
    let denied = s.run(&script, false);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("network access not allowed"));

    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let mut request = [0_u8; 16];
            let (count, peer) = socket.recv_from(&mut request).unwrap();
            assert_eq!(&request[..count], b"PING\0");
            socket.send_to(b"GAK\0", peer).unwrap();
        }
    });
    for engine in ["ast", "vm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .args([
                "run",
                script.to_str().unwrap(),
                "--engine",
                engine,
                "--allow-connect",
                &endpoint,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        let output = stdout(&out);
        assert!(output.contains(&format!("udp://{endpoint}")), "{output}");
        assert!(output.contains("decoder: u16le, value: 16711"), "{output}");
        assert!(output.ends_with("4\n"), "{output}");
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["build", script.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "exec",
            bundle.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(&format!("udp://{endpoint}")));
    assert!(stdout(&out).ends_with("4\n"));

    let missing = s.write(
        "missing-udp.gak",
        &format!("import std.net\nprint net.datagram(\"127.0.0.1\", {port}, \"PING\", 4, 2000)\n"),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            missing.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("net.connect was not declared"));
}

#[test]
fn udp_datagram_enforces_response_limit_and_timeout() {
    let s = Sandbox::new();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "udp-large.gak",
        &format!("requires {{ net.connect }}\nimport std.net\nprint net.datagram(\"127.0.0.1\", {port}, \"X\", 4, 2000)\n"),
    );
    let server = std::thread::spawn(move || {
        let mut request = [0_u8; 16];
        let (_, peer) = socket.recv_from(&mut request).unwrap();
        socket.send_to(b"ABCDE", peer).unwrap();
    });
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            script.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("LimitExceeded"), "{}", stderr(&out));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "udp-slow.gak",
        &format!("requires {{ net.connect }}\nimport std.net\nprint net.datagram(\"127.0.0.1\", {port}, \"X\", 4, 100)\n"),
    );
    let server = std::thread::spawn(move || {
        let mut request = [0_u8; 16];
        socket.recv_from(&mut request).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    });
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            script.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("UDP exchange timed out"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn http_request_exposes_status_headers_and_body_in_ast_vm_bundle() {
    let s = Sandbox::new();
    let (port, server) = local_http_post_server(3);
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "http-request.gak",
        &format!(
            "requires {{ net.connect, case.write }}\nfrom std.net import request, status, headers, body\nfrom std.binary import from_hex, size, deep\nlet reply: HttpResponse = request(\n    \"POST\",\n    \"http://{endpoint}/probe\",\n    [\"X-Research: Galeikan\"],\n    from_hex(\"47 41 4b\"),\n    3,\n    10000,\n)\nlet traces: List<str> = headers(reply, \"x-trace\")\nprint status(reply)\nprint traces[0]\nprint traces[1]\nprint size(body(reply))\nimpact reply\nimpact deep(body(reply), 0, \"u16le\")\n"
        ),
    );
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            fs::remove_file(&script).unwrap();
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("http-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command
            .arg("--allow-connect")
            .arg(&endpoint)
            .arg("--case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with("201\nalpha\nbeta\n3\nimpact {"));
        assert!(stdout(&output).contains("value: 23117"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        assert_eq!(document["events"][0]["value"]["$galeikan"], "HttpResponse");
        assert_eq!(
            document["events"][0]["value"]["body"]["lineage"][0]["operation"],
            "capture"
        );
        assert_eq!(document["events"][0]["value"]["request"]["size"], 3);
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
        if engine == "ast" {
            let mut altered = document;
            altered["events"][0]["value"]["request"]["sha256"] = serde_json::json!("0".repeat(64));
            fs::write(&case, serde_json::to_vec(&altered).unwrap()).unwrap();
            let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("verify-case")
                .arg(&case)
                .output()
                .unwrap();
            assert!(!rejected.status.success());
        }
    }
    server.join().unwrap();
}

#[test]
fn http_request_rejects_unsafe_methods_headers_and_body() {
    let s = Sandbox::new();
    let endpoint = "127.0.0.1:1";
    for (name, method, headers, body, expected) in [
        ("method", "TRACE", "[]", "\"\"", "HTTP method must be"),
        (
            "managed-header",
            "POST",
            "[\"Host: other\"]",
            "\"x\"",
            "managed by the runtime",
        ),
        (
            "invalid-header",
            "POST",
            "[\"broken\"]",
            "\"x\"",
            "HTTP header needs name: value",
        ),
        ("get-body", "GET", "[]", "\"x\"", "must have an empty body"),
    ] {
        let script = s.write(&format!("{name}.gak"), &format!(
            "requires {{ net.connect }}\nfrom std.net import request\nprint request(\"{method}\", \"http://{endpoint}/\", {headers}, {body}, 4, 2000)\n"
        ));
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .arg("--allow-connect")
            .arg(endpoint)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name} unexpectedly passed");
        assert!(
            stderr(&output).contains(expected),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn http_head_ignores_advertised_entity_length() {
    let s = Sandbox::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = client.read(&mut chunk).unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(request.starts_with(b"HEAD /probe HTTP/1.1\r\n"));
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let script = s.write("head.gak", &format!(
        "requires {{ net.connect }}\nfrom std.net import request, status, body\nfrom std.binary import size\nlet reply = request(\"HEAD\", \"http://{endpoint}/probe\", [], \"\", 0, 2000)\nprint status(reply)\nprint size(body(reply))\n"
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "200\n0\n");
}

#[test]
fn bounded_http_fetch_preserves_body_and_provenance_in_ast_vm_bundle() {
    let s = Sandbox::new();
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nGAK\0";
    let (port, server) = local_http_server(vec![reply, reply, reply]);
    let endpoint = format!("127.0.0.1:{port}");
    let url = format!("http://{endpoint}/sample?tag=1");
    let script = s.write(
        "http.gak",
        &format!(
            "requires {{ net.connect }}\nfrom std.net import fetch\nfrom std.binary import deep, size\nlet source = fetch(\"{url}\", 4, 10000)\nimpact deep(source, 0, \"u16le\")\nprint size(source)\n"
        ),
    );
    let denied = s.run(&script, false);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("network access not allowed"));
    for engine in ["ast", "vm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .args([
                "run",
                script.to_str().unwrap(),
                "--engine",
                engine,
                "--allow-connect",
                &endpoint,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        let output = stdout(&out);
        assert!(output.contains("HTTP 200"), "{output}");
        assert!(output.contains(&url), "{output}");
        assert!(output.contains("decoder: u16le, value: 16711"), "{output}");
        assert!(output.ends_with("4\n"), "{output}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["build", script.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "exec",
            bundle.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("HTTP 200"));
    assert!(stdout(&out).ends_with("4\n"));

    let missing = s.write(
        "missing-http.gak",
        &format!("import std.net\nprint net.fetch(\"{url}\", 4, 2000)\n"),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            missing.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("net.connect was not declared"));
}

#[test]
fn imported_network_module_runs_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nGAK";
    let (port, server) = local_http_server(vec![reply, reply, reply]);
    let endpoint = format!("127.0.0.1:{port}");
    s.write(
        "client.gak",
        "requires { net.connect }\nfrom std.net import fetch\nfn get(url: str) -> Source = fetch(url, 3, 10000)\n",
    );
    let script = s.write(
        "main.gak",
        &format!(
            "requires {{ net.connect }}\nimport client\nfrom std.binary import sha256\nprint sha256(client.get(\"http://{endpoint}/sample\"))\n"
        ),
    );
    for engine in ["ast", "vm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .args([
                "run",
                script.to_str().unwrap(),
                "--engine",
                engine,
                "--allow-connect",
                &endpoint,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out).trim().len(), 64);
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["build", script.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    fs::remove_file(s.dir.join("client.gak")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "exec",
            script.with_extension("gakb").to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim().len(), 64);
}

#[test]
fn http_fetch_rejects_redirects_and_oversized_bodies() {
    let s = Sandbox::new();
    for (name, response, limit, message) in [
        (
            "redirect",
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .as_slice(),
            4,
            "HTTP redirect refused",
        ),
        (
            "oversized-length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nABCDE"
                .as_slice(),
            4,
            "LimitExceeded",
        ),
        (
            "oversized-chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nABCDE\r\n0\r\n\r\n"
                .as_slice(),
            4,
            "LimitExceeded",
        ),
    ] {
        let (port, server) = local_http_server(vec![response]);
        let endpoint = format!("127.0.0.1:{port}");
        let script = s.write(
            &format!("{name}.gak"),
            &format!(
                "requires {{ net.connect }}\nimport std.net\nprint net.fetch(\"http://{endpoint}/sample\", {limit}, 2000)\n"
            ),
        );
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .args([
                "run",
                script.to_str().unwrap(),
                "--allow-connect",
                &endpoint,
            ])
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(!out.status.success());
        assert!(stderr(&out).contains(message), "{}", stderr(&out));
    }
    for (name, url, message) in [
        ("scheme", "file:///etc/passwd", "must use http or https"),
        (
            "credentials",
            "http://u:p@127.0.0.1/",
            "credentials are not allowed",
        ),
        (
            "fragment",
            "http://127.0.0.1/#hidden",
            "fragments are not allowed",
        ),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!(
                "requires {{ net.connect }}\nimport std.net\nprint net.fetch(\"{url}\", 4, 2000)\n"
            ),
        );
        let out = s.run(&script, false);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(message), "{}", stderr(&out));
    }
}

#[test]
fn http_fetch_keeps_error_status_body_and_times_out_on_slow_body() {
    let s = Sandbox::new();
    let (port, server) = local_http_server(vec![
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nConnection: close\r\n\r\nERR",
    ]);
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "http-404.gak",
        &format!(
            "requires {{ net.connect }}\nimport std.net\nimport std.binary\nimpact binary.deep(net.fetch(\"http://{endpoint}/missing\", 3, 2000), 0, \"u8\")\n"
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            script.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("HTTP 404"));
    assert!(stdout(&out).contains("value: 69"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let server = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request_start = [0_u8; 1];
        if client.read_exact(&mut request_start).is_ok() {
            let _ = client
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n");
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    });
    let script = s.write(
        "http-slow.gak",
        &format!(
            "requires {{ net.connect }}\nimport std.net\nprint net.fetch(\"http://{endpoint}/slow\", 4, 500)\n"
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args([
            "run",
            script.to_str().unwrap(),
            "--allow-connect",
            &endpoint,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("timed out"), "{}", stderr(&out));
}

#[test]
fn tcp_exchange_enforces_response_limit_and_timeout() {
    let s = Sandbox::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "large.gak",
        &format!(
            "requires {{ net.connect }}\nimport std.net\nprint net.exchange(\"127.0.0.1\", {port}, \"X\", 4, 2000)\n"
        ),
    );
    let server = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        client.read_to_end(&mut request).unwrap();
        client.write_all(b"ABCDE").unwrap();
    });
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("LimitExceeded"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("127.0.0.1:{port}");
    let script = s.write(
        "slow.gak",
        &format!(
            "requires {{ net.connect }}\nimport std.net\nprint net.exchange(\"127.0.0.1\", {port}, \"X\", 4, 100)\n"
        ),
    );
    let server = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        client.read_to_end(&mut request).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    });
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .arg("--allow-connect")
        .arg(&endpoint)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("TCP exchange timed out"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn hex_bytes_form_a_hashable_memory_source() {
    let s = Sandbox::new();
    let script = s.write(
        "memory.gak",
        "import std.binary\nlet data = binary.from_hex(\"47 41 4b 00\")\nlet source = binary.snapshot(data)\nprint binary.size(data)\nprint binary.size(source)\nprint binary.sha256(data)\nprint binary.sha256(source)\nimpact binary.deep(source, 0, \"u16le\")\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    let lines: Vec<_> = stdout(&out).lines().map(str::to_string).collect();
    assert_eq!(lines[0], "4");
    assert_eq!(lines[1], "4");
    assert_eq!(lines[2], lines[3]);
    assert!(lines[4].contains("range: [0..2), decoder: u16le, value: 16711"));

    let invalid = s.write(
        "invalid-hex.gak",
        "import std.binary\nprint binary.from_hex(\"é\")\n",
    );
    let out = s.run(&invalid, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid hex data"));
}

#[test]
fn binary_views_diffs_and_observation_values_preserve_evidence() {
    let s = Sandbox::new();
    let script = s.write(
        "binary-evidence.gak",
        "import std.binary\nlet left = binary.snapshot(binary.from_hex(\"00 01 02 03\"))\nlet right = binary.snapshot(binary.from_hex(\"00 ff 02 03 04\"))\nlet view = binary.view(left, 1, 2)\nlet nested = binary.view(view, 1, 1)\nlet observation = binary.deep(view, 0, \"u16le\")\nprint binary.size(view)\nprint binary.extract(left, 1, 2)\nprint binary.extract(nested, 0, 1)\nprint binary.sha256(view) == binary.sha256(binary.extract(left, 1, 2))\nprint binary.value(observation)\nprint binary.offset(observation)\nprint binary.width(observation)\nimpact observation\nimpact binary.diff(left, right, 2)\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    let output = stdout(&out);
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(
        &lines[..7],
        &[
            "2",
            "bytes(2 bytes, hex:0102)",
            "bytes(1 bytes, hex:02)",
            "true",
            "513",
            "0",
            "2"
        ]
    );
    assert!(lines[7].contains("view of sha256:"), "{output}");
    assert!(lines[7].contains("[1..3)"), "{output}");
    assert!(lines[8].contains("left_sha256:"), "{output}");
    assert!(lines[8].contains("right_sha256:"), "{output}");
    assert!(lines[8].contains("offsets: [1, 4]"), "{output}");

    let limit = s.write(
        "diff-limit.gak",
        "import std.binary\nlet a = binary.snapshot(binary.from_hex(\"00 01\"))\nlet b = binary.snapshot(binary.from_hex(\"ff ff\"))\nimpact binary.diff(a, b, 1)\n",
    );
    let out = s.run(&limit, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("LimitExceeded: too many differences"));

    let out_of_bounds = s.write(
        "view-bounds.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nprint binary.view(source, 1, 1)\n",
    );
    let out = s.run(&out_of_bounds, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("out of bounds"));

    let large_value = s.write(
        "large-value.gak",
        "import std.binary\nfn read() -> Result<i64> = binary.value(binary.deep(binary.snapshot(binary.from_hex(\"ff ff ff ff ff ff ff ff\")), 0, \"u64le\"))\nprint read()\n",
    );
    let out = s.run(&large_value, false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("error(Observation value does not fit i64)"));
}

#[test]
fn binary_splice_inserts_removes_and_verifies_case_lineage() {
    let s = Sandbox::new();
    let script = s.write("splice.gak", include_str!("../examples/splice.gak"));
    let mut expected_events = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            fs::remove_file(&script).unwrap();
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("splice-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.args(["--engine", engine]);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(
            output.status.success(),
            "{mode}/{engine}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).starts_with("4142ff004344\n414344\n41434445\n"));
        let report: serde_json::Value = serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let events = &report["events"];
        let lineage = events[0]["value"]["source_lineage"].as_array().unwrap();
        assert_eq!(lineage.len(), 4);
        assert_eq!(lineage[1]["operation"], "splice");
        assert_eq!(lineage[1]["start"], 2);
        assert_eq!(lineage[1]["end"], 2);
        assert_eq!(lineage[1]["inserted_size"], 2);
        assert_eq!(lineage[2]["start"], 1);
        assert_eq!(lineage[2]["end"], 4);
        assert_eq!(lineage[2]["inserted_size"], 0);
        assert_eq!(lineage[3]["start"], 3);
        assert_eq!(lineage[3]["inserted_size"], 1);
        if let Some(previous) = &expected_events {
            assert_eq!(events, previous);
        }
        expected_events = Some(events.clone());
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
        if mode == "run" && engine == "ast" {
            let mut tampered = report.clone();
            tampered["events"][0]["value"]["source_lineage"][1]["inserted_size"] =
                serde_json::json!(1);
            fs::write(&case, serde_json::to_vec(&tampered).unwrap()).unwrap();
            let invalid = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("verify-case")
                .arg(&case)
                .output()
                .unwrap();
            assert!(!invalid.status.success());
            assert!(stderr(&invalid).contains("case splice changed bytes outside its range"));
            let mut tampered = report.clone();
            tampered["events"][0]["value"]["source_lineage"][1]["replacement_sha256"] =
                serde_json::json!("0".repeat(64));
            fs::write(&case, serde_json::to_vec(&tampered).unwrap()).unwrap();
            let invalid = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("verify-case")
                .arg(&case)
                .output()
                .unwrap();
            assert!(!invalid.status.success());
            assert!(stderr(&invalid).contains("case splice replacement hash mismatch"));
        }
    }

    s.write(
        "invalid.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nprint binary.splice(source, 0, 0, binary.from_hex(\"\"))\n",
    );
    let invalid = s.run(&s.dir.join("invalid.gak"), false);
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("splice must insert or remove at least one byte"));
    s.write(
        "out-of-bounds.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nprint binary.splice(source, 1, 1, binary.from_hex(\"ff\"))\n",
    );
    let invalid = s.run(&s.dir.join("out-of-bounds.gak"), false);
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("out of bounds"));

    let mixed = s.write(
        "mixed.gak",
        "import std.binary\nimport std.bytes\nlet source = binary.snapshot(bytes.from_hex(\"41 42 43 44\"))\nlet result = binary.splice(source, 1, 2, bytes.from_hex(\"99\"))\nprint bytes.to_hex(binary.extract(result, 0, binary.size(result)))\n",
    );
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&mixed, engine, false, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), "419944\n");
    }

    s.bytes("large.bin", &vec![0_u8; 1024 * 1024 + 1]);
    let oversized = s.write(
        "oversized-splice.gak",
        "requires { file.read }\nimport std.binary\nlet source = binary.analyze(\"large.bin\", 1048577)\nlet insertion = binary.extract(source, 0, 1048577)\nprint binary.splice(source, 0, 0, insertion)\n",
    );
    let invalid = s.run(&oversized, true);
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("LimitExceeded: splice insertion exceeds 1048576 bytes"));
}

#[test]
fn binary_patch_preserves_parent_evidence_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let script = s.write("patch.gak", include_str!("../examples/patch.gak"));
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).contains("patch of sha256:"));
    assert!(stdout(&ast).contains("decoder: u16le, value: 16717"));
    assert!(stdout(&ast).contains("offsets: [1, 2]"));
    assert!(stdout(&ast).contains("left_sha256:"));
    assert!(stdout(&ast).contains("right_sha256:"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&ast), stdout(&bundled));

    let empty = s.write(
        "empty_patch.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nprint binary.patch(source, 0, binary.from_hex(\"\"))\n",
    );
    let out = s.run(&empty, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("patch data must not be empty"));

    let beyond = s.write(
        "beyond_patch.gak",
        "import std.binary\nlet source = binary.snapshot(binary.from_hex(\"00\"))\nprint binary.patch(source, 1, binary.from_hex(\"ff\"))\n",
    );
    let out = s.run(&beyond, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("out of bounds"));

    s.bytes("large.bin", &vec![0_u8; 1024 * 1024 + 1]);
    let oversized = s.write(
        "oversized_patch.gak",
        "requires { file.read }\nimport std.binary\nlet source = binary.analyze(\"large.bin\", 1048577)\nlet replacement = binary.extract(source, 0, 1048577)\nprint binary.patch(source, 0, replacement)\n",
    );
    let out = s.run(&oversized, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("LimitExceeded: patch exceeds 1048576 bytes"));

    let depth = s.write(
        "source_depth.gak",
        "import std.binary\nimport std.iter\nvar current = binary.snapshot(binary.from_hex(\"00\"))\nfor index in iter.range(64) {\n    current = binary.view(current, 0, 1)\n}\nprint binary.patch(current, 0, binary.from_hex(\"ff\"))\n",
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&depth, engine, false, &[]);
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("LimitExceeded: Source derivation depth exceeds 64"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn bytes_module_transforms_are_typed_and_work_in_both_engines_and_bundle() {
    let s = Sandbox::new();
    let script = s.write("bytes.gak", include_str!("../examples/bytes.gak"));
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).starts_with("4d5a4141\n77\n4d5a4141\n"));
    assert!(stdout(&ast).contains("decoder: u16le, value: 23117"));

    let request = r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"6d7a"}]}"#;
    for engine in ["ast", "vm"] {
        let result = call_json(&script, "unmask", engine, request);
        assert!(result.status.success(), "{}", stderr(&result));
        let body: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(body["value"]["hex"], "4d5a");
    }

    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&ast), stdout(&bundled));
    let called = call_json(&bundle, "unmask", "vm", request);
    assert!(called.status.success(), "{}", stderr(&called));
    let body: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
    assert_eq!(body["value"]["hex"], "4d5a");

    let bad_type = s.write(
        "bytes_type.gak",
        "import std.bytes\nprint bytes.concat(1, 2)\n",
    );
    let result = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&bad_type)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(stderr(&result).contains("expected bytes, got i64"));

    for (name, body, expected) in [
        (
            "negative_repeat",
            "print bytes.repeat(bytes.from_hex(\"41\"), -1)",
            "repeat count must not be negative",
        ),
        (
            "empty_key",
            "print bytes.xor(bytes.from_hex(\"41\"), bytes.from_hex(\"\"))",
            "xor key must not be empty",
        ),
        (
            "bad_index",
            "print bytes.at(bytes.from_hex(\"41\"), 1)",
            "byte index out of range",
        ),
        (
            "too_many",
            "print bytes.repeat(bytes.from_hex(\"41\"), 1048577)",
            "repeat count exceeds 1048576",
        ),
    ] {
        let path = s.write(
            &format!("{name}.gak"),
            &format!("import std.bytes\n{body}\n"),
        );
        let out = s.run(&path, false);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(expected), "{}", stderr(&out));
    }
}

#[test]
fn packed_fields_round_trip_in_ast_vm_bundle_and_python_call() {
    let s = Sandbox::new();
    let script = s.write(
        "packed.gak",
        "from std.bytes import pack, concat, to_hex\nfrom std.binary import snapshot, deep, value\nfn encode(n: i64) -> bytes = pack(n, \"u32le\")\nlet payload = concat(pack(4660, \"u16be\"), encode(305419896))\nprint to_hex(payload)\nprint value(deep(snapshot(payload), 0, \"u16be\"))\nprint value(deep(snapshot(payload), 2, \"u32le\"))\n",
    );
    let expected = "123478563412\n4660\n305419896\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
        let called = call_json(
            &script,
            "encode",
            engine,
            r#"{"version":1,"args":[305419896]}"#,
        );
        assert!(called.status.success(), "{}", stderr(&called));
        let body: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
        assert_eq!(body["value"]["hex"], "78563412");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["build", script.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["exec", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);
    let called = call_json(
        &bundle,
        "encode",
        "vm",
        r#"{"version":1,"args":[305419896]}"#,
    );
    assert!(called.status.success(), "{}", stderr(&called));
    let body: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
    assert_eq!(body["value"]["hex"], "78563412");

    let bad_type = s.write(
        "bad-pack-type.gak",
        "import std.bytes\nprint bytes.pack(\"1\", \"u8\")\n",
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .args(["check", bad_type.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!checked.status.success());
    assert!(stderr(&checked).contains("expects i64 or u64 value, got str"));
    for (name, expression, message) in [
        ("negative", "bytes.pack(-1, \"u8\")", "nonnegative"),
        ("overflow", "bytes.pack(256, \"u8\")", "out of range"),
        ("decoder", "bytes.pack(1, \"u128le\")", "encoding must"),
    ] {
        let path = s.write(
            &format!("{name}.gak"),
            &format!("import std.bytes\nprint {expression}\n"),
        );
        let out = s.run(&path, false);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(message), "{}", stderr(&out));
    }
}

#[test]
fn audit_rules_produce_traceable_findings() {
    let s = Sandbox::new();
    let script = s.write(
        "audit.gak",
        "import std.binary\nimport std.audit\nlet source = binary.snapshot(binary.from_hex(\"10 00 47 41\"))\nlet length = binary.deep(source, 0, \"u16le\")\nlet within = audit.bound(length, 0, 32, \"header.length\")\nlet mismatch = audit.expect(length, 8, \"header.expected\")\nprint audit.passed(within)\nprint audit.failed(mismatch)\nimpact within\nimpact mismatch\n",
    );
    let out = s.run(&script, false);
    assert!(out.status.success(), "{}", stderr(&out));
    let output = stdout(&out);
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(&lines[..2], &["true", "true"]);
    assert!(lines[2].contains("rule: \"header.length\", status: pass"));
    assert!(lines[2].contains("expected: \"between 0 and 32\""));
    assert!(lines[2].contains("actual: 16"));
    assert!(lines[2].contains("sha256:"));
    assert!(lines[2].contains("range: [0..2), decoder: u16le"));
    assert!(lines[3].contains("rule: \"header.expected\", status: fail"));

    let invalid_range = s.write(
        "audit-range.gak",
        "import std.binary\nimport std.audit\nlet source = binary.snapshot(binary.from_hex(\"10\"))\nprint audit.bound(binary.deep(source, 0, \"u8\"), 10, 1, \"bad.range\")\n",
    );
    let out = s.run(&invalid_range, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("maximum must be at least minimum"));

    let invalid_rule = s.write(
        "audit-rule.gak",
        "import std.binary\nimport std.audit\nlet source = binary.snapshot(binary.from_hex(\"10\"))\nprint audit.expect(binary.deep(source, 0, \"u8\"), 16, \"bad\\nrule\")\n",
    );
    let out = s.run(&invalid_rule, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("rule id must be"));

    let wrong_type = s.write(
        "audit-type.gak",
        "import std.audit\nprint audit.passed(42)\n",
    );
    let out = s.run(&wrong_type, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected Finding, got i64"));
}

#[test]
fn binary_profile_metadata_is_simple_typed_and_matches_ast_vm_bundle() {
    let s = Sandbox::new();
    let section_table = 0x80 + 4 + 20 + 0xf0;
    let mut pe = vec![0_u8; section_table + 40];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    let elf = elf64_dynamic_symbol_fixture();
    let mut pe_arm64 = pe.clone();
    pe_arm64[0x84..0x86].copy_from_slice(&0xaa64_u16.to_le_bytes());
    let mut elf_arm64 = elf.clone();
    elf_arm64[18..20].copy_from_slice(&183_u16.to_le_bytes());
    let mut elf_riscv = elf.clone();
    elf_riscv[18..20].copy_from_slice(&243_u16.to_le_bytes());
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let script = s.write(
        "profile.gak",
        &format!(
            "from std.binary import from_hex, snapshot\n\
         from std.formats import probe, kind, bits, endian, arch\n\
         let pe: Format = probe(snapshot(from_hex(\"{}\")))\n\
         let elf: Format = probe(snapshot(from_hex(\"{}\")))\n\
         let pe_arm64: Format = probe(snapshot(from_hex(\"{}\")))\n\
         let elf_arm64: Format = probe(snapshot(from_hex(\"{}\")))\n\
         let elf_riscv: Format = probe(snapshot(from_hex(\"{}\")))\n\
         print kind(pe)\nprint bits(pe)\nprint endian(pe)\nprint arch(pe)\n\
         print kind(elf)\nprint bits(elf)\nprint endian(elf)\nprint arch(elf)\n\
         print arch(pe_arm64)\nprint arch(elf_arm64)\nprint arch(elf_riscv)\n",
            hex(&pe),
            hex(&elf),
            hex(&pe_arm64),
            hex(&elf_arm64),
            hex(&elf_riscv)
        ),
    );
    let expected = "pe\n64\nlittle\nx86_64\nelf\n64\nlittle\nx86_64\naarch64\naarch64\nriscv\n";
    for engine in ["ast", "vm"] {
        let output = s.run_engine(&script, engine, false, &[]);
        assert!(output.status.success(), "{engine}: {}", stderr(&output));
        assert_eq!(stdout(&output), expected, "{engine}");
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), expected);
    let wrong = s.write(
        "wrong-profile.gak",
        "from std.formats import bits\nprint bits(42)\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("check")
        .arg(&wrong)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("expected Format, got i64"));
}

#[test]
fn pe_section_inspection_preserves_source_and_matches_both_engines() {
    let s = Sandbox::new();
    let section_table = 0x80 + 4 + 20 + 0xf0;
    let payload = section_table + 40;
    let mut bytes = vec![0_u8; payload + 4];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[0x98 + 16..0x98 + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_table..section_table + 5].copy_from_slice(b".text");
    bytes[section_table + 8..section_table + 12].copy_from_slice(&8_u32.to_le_bytes());
    bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_table + 16..section_table + 20].copy_from_slice(&4_u32.to_le_bytes());
    bytes[section_table + 20..section_table + 24].copy_from_slice(&(payload as u32).to_le_bytes());
    bytes[section_table + 36..section_table + 40].copy_from_slice(&0x60000020_u32.to_le_bytes());
    bytes[payload..].copy_from_slice(b"GAK\0");
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let script = s.write("section.gak", &format!(
        "import std.binary\nimport std.formats\nlet source = binary.snapshot(binary.from_hex(\"{hex}\"))\nlet report = formats.probe(source)\nlet section = formats.section(report, 0)\nprint formats.name(section)\nprint formats.offset(section)\nprint formats.size(section)\nprint formats.address(section)\nprint formats.flags(section)\nimpact section\nimpact binary.deep(formats.data(section), 0, \"u16le\")\nprint formats.rva(report, 4096, 2)\nimpact binary.deep(formats.rva(report, 4096, 2), 0, \"u16le\")\nimpact binary.deep(formats.entry_view(report, 2), 0, \"u16le\")\n"
    ));
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).contains(".text\n432\n4\n0x1000\n0x60000020\n"));
    assert!(stdout(&ast).contains("decoder: u16le, value: 16711"));
    assert!(stdout(&ast).contains("view of sha256:"));
    assert!(stdout(&ast).contains("PE RVA 0x1000"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&ast), stdout(&compiled));

    let truncated = bytes[..payload]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let incomplete = s.write("incomplete.gak", &format!(
        "import std.binary\nimport std.formats\nlet source = binary.snapshot(binary.from_hex(\"{truncated}\"))\nlet section = formats.section(formats.probe(source), 0)\nprint formats.name(section)\nprint formats.data(section)\n"
    ));
    let out = s.run(&incomplete, false);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), ".text\n");
    assert!(stderr(&out).contains("section data outside captured Source"));
}

#[test]
fn pe_overlay_is_a_traceable_source_in_ast_vm_bundle_and_case() {
    let s = Sandbox::new();
    let section_table = 0x80 + 4 + 20 + 0xf0;
    let mut bytes = vec![0_u8; 0x207];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[section_table + 16..section_table + 20].copy_from_slice(&4_u32.to_le_bytes());
    bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(b"CODE");
    bytes[0x204..].copy_from_slice(b"GAK");
    s.bytes("sample.exe", &bytes);
    let script = s.write(
        "overlay.gak",
        "requires { file.read, case.write }\nfrom std.binary import analyze, deep, extract, size\nfrom std.bytes import to_hex\nfrom std.formats import probe, overlay\nlet tail: Source = overlay(probe(analyze(\"sample.exe\", 4096)))\nprint size(tail)\nprint to_hex(extract(tail, 0, size(tail)))\nimpact deep(tail, 0, \"u8\")\n",
    );
    let mut expected = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("overlay-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let out = command
            .arg("--allow-read")
            .arg(&s.dir)
            .arg("--case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).starts_with("3\n47414b\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let lineage = &document["events"][0]["value"]["source_lineage"];
        assert_eq!(lineage[1]["operation"], "view");
        assert_eq!(lineage[1]["start"], 0x204);
        assert_eq!(lineage[1]["end"], 0x207);
        if let Some(previous) = &expected {
            assert_eq!(&document["events"], previous);
        }
        expected = Some(document["events"].clone());
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }

    let no_overlay = s.write(
        "empty-overlay.gak",
        "requires { file.read }\nfrom std.binary import analyze, size\nfrom std.formats import probe, overlay\nprint size(overlay(probe(analyze(\"sample.exe\", 4096))))\n",
    );
    s.bytes("sample.exe", &bytes[..0x204]);
    let empty = s.run(&no_overlay, true);
    assert!(empty.status.success(), "{}", stderr(&empty));
    assert_eq!(stdout(&empty), "0\n");
    s.bytes("sample.exe", &bytes[..0x203]);
    let incomplete = s.run(&no_overlay, true);
    assert!(!incomplete.status.success());
    assert!(stderr(&incomplete).contains("declared binary extent outside captured Source"));
}

#[test]
fn pe_certificate_payloads_and_metadata_work_in_ast_vm_bundle_and_case() {
    let s = Sandbox::new();
    let mut bytes = vec![0_u8; 0x22c];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x98 + 108..0x98 + 112].copy_from_slice(&5_u32.to_le_bytes());
    bytes[0x98 + 144..0x98 + 148].copy_from_slice(&0x208_u32.to_le_bytes());
    bytes[0x98 + 148..0x98 + 152].copy_from_slice(&32_u32.to_le_bytes());
    let section = 0x80 + 4 + 20 + 0xf0;
    bytes[section + 16..section + 20].copy_from_slice(&4_u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(b"CODE");
    bytes[0x208..0x20c].copy_from_slice(&11_u32.to_le_bytes());
    bytes[0x20c..0x20e].copy_from_slice(&0x200_u16.to_le_bytes());
    bytes[0x20e..0x210].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0x210..0x213].copy_from_slice(b"ABC");
    bytes[0x218..0x21c].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x21c..0x21e].copy_from_slice(&0x100_u16.to_le_bytes());
    bytes[0x21e..0x220].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x220..0x224].copy_from_slice(b"DATA");
    bytes[0x228..].copy_from_slice(b"TAIL");
    s.bytes("sample.exe", &bytes);
    let script = s.write(
        "certificates.gak",
        "requires { file.read, case.write }\nfrom std.binary import analyze, deep, extract, size\nfrom std.bytes import to_hex\nfrom std.formats import probe, certificate_count, certificate_data, certificate_offset, certificate_size, certificate_revision, certificate_type\nlet report: Format = probe(analyze(\"sample.exe\", 4096))\nlet first: Source = certificate_data(report, 0)\nprint certificate_count(report)\nprint certificate_offset(report, 0)\nprint certificate_size(report, 0)\nprint certificate_revision(report, 0)\nprint certificate_type(report, 0)\nprint to_hex(extract(first, 0, size(first)))\nprint to_hex(extract(certificate_data(report, 1), 0, certificate_size(report, 1)))\nimpact deep(first, 0, \"u8\")\n",
    );
    let mut expected = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let target = if mode == "exec" {
            let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
                .arg("build")
                .arg(&script)
                .output()
                .unwrap();
            assert!(built.status.success(), "{}", stderr(&built));
            script.with_extension("gakb")
        } else {
            script.clone()
        };
        let case = s.dir.join(format!("certificate-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(target);
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let out = command
            .arg("--allow-read")
            .arg(&s.dir)
            .arg("--case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).starts_with("2\n528\n3\n512\n2\n414243\n44415441\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let lineage = &document["events"][0]["value"]["source_lineage"];
        assert_eq!(lineage[1]["operation"], "view");
        assert_eq!(lineage[1]["start"], 0x210);
        assert_eq!(lineage[1]["end"], 0x213);
        if let Some(previous) = &expected {
            assert_eq!(&document["events"], previous);
        }
        expected = Some(document["events"].clone());
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }
}

#[test]
fn elf_entry_view_maps_load_segment_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let mut bytes = vec![0_u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&16_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&32_u64.to_le_bytes());
    bytes[0x100..0x104].copy_from_slice(b"GAK\0");
    s.bytes("sample.elf", &bytes);
    let script = s.write(
        "entry.gak",
        "requires { file.read }\nimport std.binary\nimport std.formats\nlet source = binary.analyze(\"sample.elf\", 1024)\nlet report = formats.probe(source)\nlet entry = formats.entry_view(report, 4)\nimpact binary.deep(entry, 0, \"u16le\")\nprint binary.sha256(entry)\nprint binary.sha256(formats.va(report, 4198400, 4))\n",
    );
    let ast = s.run_engine(&script, "ast", true, &[]);
    let vm = s.run_engine(&script, "vm", true, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).contains("ELF VA 0x401000"));
    assert!(stdout(&ast).contains("decoder: u16le, value: 16711"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .arg("--allow-read")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&ast), stdout(&compiled));

    let invalid = s.write(
        "bss.gak",
        "requires { file.read }\nimport std.binary\nimport std.formats\nlet report = formats.probe(binary.analyze(\"sample.elf\", 1024))\nprint formats.va(report, 4198416, 1)\n",
    );
    let result = s.run(&invalid, true);
    assert!(!result.status.success());
    assert!(stderr(&result).contains("no file-backed bytes"));
}

#[test]
fn elf_needed_libraries_are_available_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let mut bytes = vec![0_u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400100_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400100_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x100_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x100_u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&2_u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x120_u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400120_u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&80_u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&80_u64.to_le_bytes());
    for (index, (tag, value)) in [(5, 0x400180), (10, 32), (1, 1), (1, 11), (0, 0)]
        .into_iter()
        .enumerate()
    {
        let offset = 0x120 + index * 16;
        bytes[offset..offset + 8].copy_from_slice(&(tag as u64).to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&(value as u64).to_le_bytes());
    }
    bytes[0x180..0x195].copy_from_slice(b"\0libc.so.6\0libm.so.6\0");
    s.bytes("deps.elf", &bytes);
    let script = s.write("needed.gak", include_str!("../examples/needed.gak"));
    let ast = s.run_engine(&script, "ast", true, &["deps.elf"]);
    let vm = s.run_engine(&script, "vm", true, &["deps.elf"]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), "libc.so.6\nlibm.so.6\n");
    assert_eq!(stdout(&ast), stdout(&vm));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--allow-read")
        .arg(&s.dir)
        .arg("--")
        .arg("deps.elf")
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&ast), stdout(&bundled));

    let cross_format = s.write(
        "dependencies.gak",
        include_str!("../examples/dependencies.gak"),
    );
    for engine in ["ast", "vm"] {
        let result = s.run_engine(&cross_format, engine, true, &["deps.elf"]);
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(stdout(&result), "libc.so.6\nlibm.so.6\n");
    }
}

#[test]
fn elf_dynamic_symbols_are_available_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    s.bytes("symbols.elf", &elf64_dynamic_symbol_fixture());
    let script = s.write(
        "symbols.gak",
        "requires { file.read }\nfrom std.binary import analyze\nfrom std.formats import probe, symbol_count, symbol_name, symbol_role, symbol_type, symbol_binding, symbol_visibility, symbol_defined, symbol_address, symbol_size, symbol_section, symbol_summary\nlet report = probe(analyze(\"symbols.elf\", 1024))\nprint symbol_count(report)\nprint symbol_name(report, 1)\nprint symbol_role(report, 1)\nprint symbol_type(report, 1)\nprint symbol_defined(report, 1)\nprint symbol_name(report, 2)\nprint symbol_role(report, 2)\nprint symbol_binding(report, 2)\nprint symbol_visibility(report, 2)\nprint symbol_address(report, 2)\nprint symbol_size(report, 2)\nprint symbol_section(report, 2)\nprint symbol_summary(report, 2)\n",
    );
    let expected = "3\nputs\nundefined\nfunction\nfalse\ninspect\nexported\nglobal\ndefault\n0x401000\n12\n1\ninspect [exported function] @ 0x401000\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, true, &[]);
        assert!(out.status.success(), "{engine}: {}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(script.with_extension("gakb"))
        .arg("--allow-read")
        .arg(&s.dir)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&bundled), expected);
    let invalid = s.write(
        "invalid-symbol.gak",
        "requires { file.read }\nimport std.binary\nimport std.formats\nlet report = formats.probe(binary.analyze(\"symbols.elf\", 1024))\nprint formats.symbol_name(report, 3)\n",
    );
    let out = s.run(&invalid, true);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("dynamic symbol index out of range"));
}

#[test]
fn pe_imports_and_delay_imports_are_available_in_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let optional = 0x98;
    let section_table = optional + 0xf0;
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&14_u32.to_le_bytes());
    bytes[optional + 120..optional + 124].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 124..optional + 128].copy_from_slice(&40_u32.to_le_bytes());
    bytes[optional + 216..optional + 220].copy_from_slice(&0x1100_u32.to_le_bytes());
    bytes[optional + 220..optional + 224].copy_from_slice(&64_u32.to_le_bytes());
    bytes[section_table..section_table + 6].copy_from_slice(b".idata");
    bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(&0x1040_u32.to_le_bytes());
    bytes[0x20c..0x210].copy_from_slice(&0x1080_u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&0x1060_u32.to_le_bytes());
    bytes[0x240..0x248].copy_from_slice(&0x10a0_u64.to_le_bytes());
    bytes[0x248..0x250].copy_from_slice(&(1_u64 << 63 | 7).to_le_bytes());
    bytes[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
    bytes[0x2a2..0x2ae].copy_from_slice(b"CreateFileW\0");
    bytes[0x300..0x304].copy_from_slice(&1_u32.to_le_bytes());
    bytes[0x304..0x308].copy_from_slice(&0x1160_u32.to_le_bytes());
    bytes[0x30c..0x310].copy_from_slice(&0x1150_u32.to_le_bytes());
    bytes[0x310..0x314].copy_from_slice(&0x1140_u32.to_le_bytes());
    bytes[0x340..0x348].copy_from_slice(&0x1180_u64.to_le_bytes());
    bytes[0x348..0x350].copy_from_slice(&(1_u64 << 63 | 9).to_le_bytes());
    bytes[0x360..0x36b].copy_from_slice(b"USER32.dll\0");
    bytes[0x382..0x38e].copy_from_slice(b"MessageBoxA\0");
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write("imports.gak", &format!(
        "import std.binary\nimport std.formats\nimport std.iter\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\nprint formats.dependency_count(report)\nprint formats.dependency_name(report, 0)\nprint formats.import_count(report)\nfor index in iter.range(formats.import_count(report)) {{\n    print formats.import_summary(report, index)\n    print formats.import_library(report, index)\n    print formats.import_symbol(report, index)\n    print formats.import_kind(report, index)\n}}\nprint formats.delay_dependency_count(report)\nprint formats.delay_dependency_name(report, 0)\nprint formats.delay_import_count(report)\nfor index in iter.range(formats.delay_import_count(report)) {{\n    print formats.delay_import_summary(report, index)\n    print formats.delay_import_library(report, index)\n    print formats.delay_import_symbol(report, index)\n    print formats.delay_import_kind(report, index)\n}}\n"
    ));
    let expected = "1\nKERNEL32.dll\n2\nKERNEL32.dll!CreateFileW\nKERNEL32.dll\nCreateFileW\nname\nKERNEL32.dll!#7\nKERNEL32.dll\n#7\nordinal\n1\nUSER32.dll\n2\nUSER32.dll!MessageBoxA\nUSER32.dll\nMessageBoxA\nname\nUSER32.dll!#9\nUSER32.dll\n#9\nordinal\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);

    let invalid = s.write(
        "dependency_index.gak",
        &format!("import std.binary\nimport std.formats\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\nprint formats.dependency_name(report, 1)\n"),
    );
    let out = s.run(&invalid, false);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("dependency index out of range"));

    let mut legacy = bytes.clone();
    let base = 0x1000_0000_u64;
    legacy[optional + 24..optional + 32].copy_from_slice(&base.to_le_bytes());
    legacy[0x300..0x304].fill(0);
    legacy[0x304..0x308].copy_from_slice(&((base + 0x1160) as u32).to_le_bytes());
    legacy[0x310..0x314].copy_from_slice(&((base + 0x1140) as u32).to_le_bytes());
    legacy[0x340..0x348].copy_from_slice(&(base + 0x1180).to_le_bytes());
    let legacy_hex = legacy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let legacy_script = s.write(
        "legacy_delay_imports.gak",
        &format!("from std.binary import from_hex, snapshot, value\nfrom std.formats import probe, delay_import_summary, field\nlet report = probe(snapshot(from_hex(\"{legacy_hex}\")))\nprint value(field(report, \"image_base\"))\nprint delay_import_summary(report, 0)\n"),
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&legacy_script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "268435456\nUSER32.dll!MessageBoxA\n");
    }
}

#[test]
fn pe_exports_are_available_in_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let optional = 0x98;
    let section_table = optional + 0xf0;
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&1_u32.to_le_bytes());
    bytes[optional + 112..optional + 116].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 116..optional + 120].copy_from_slice(&0x100_u32.to_le_bytes());
    bytes[section_table..section_table + 6].copy_from_slice(b".edata");
    bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x210..0x214].copy_from_slice(&5_u32.to_le_bytes());
    bytes[0x214..0x218].copy_from_slice(&3_u32.to_le_bytes());
    bytes[0x218..0x21c].copy_from_slice(&2_u32.to_le_bytes());
    bytes[0x21c..0x220].copy_from_slice(&0x1040_u32.to_le_bytes());
    bytes[0x220..0x224].copy_from_slice(&0x1060_u32.to_le_bytes());
    bytes[0x224..0x228].copy_from_slice(&0x1070_u32.to_le_bytes());
    bytes[0x240..0x244].copy_from_slice(&0x2000_u32.to_le_bytes());
    bytes[0x244..0x248].copy_from_slice(&0x1080_u32.to_le_bytes());
    bytes[0x248..0x24c].copy_from_slice(&0x3000_u32.to_le_bytes());
    bytes[0x260..0x264].copy_from_slice(&0x10a0_u32.to_le_bytes());
    bytes[0x264..0x268].copy_from_slice(&0x10a8_u32.to_le_bytes());
    bytes[0x272..0x274].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x280..0x28d].copy_from_slice(b"OTHER.Target\0");
    bytes[0x2a0..0x2a6].copy_from_slice(b"Alpha\0");
    bytes[0x2a8..0x2ad].copy_from_slice(b"Beta\0");
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write("exports.gak", &format!(
        "import std.binary\nimport std.formats\nimport std.iter\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\nprint formats.export_count(report)\nprint formats.export_address(report, 0)\nfor index in iter.range(formats.export_count(report)) {{\n    print formats.export_summary(report, index)\n    print formats.export_name(report, index)\n    print formats.export_ordinal(report, index)\n    print formats.export_target(report, index)\n    print formats.export_kind(report, index)\n}}\n"
    ));
    let expected = "3\n8192\nAlpha (#5) @ 0x2000\nAlpha\n5\n0x2000\nrva\nBeta (#6) -> OTHER.Target\nBeta\n6\nOTHER.Target\nforwarder\n#7 @ 0x3000\n#7\n7\n0x3000\nrva\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let forwarder = s.write("forwarder.gak", &format!(
        "import std.binary\nimport std.formats\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\nprint formats.export_address(report, 1)\n"
    ));
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&forwarder, engine, false, &[]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("forwarded export has no direct address"));
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);
}

#[test]
fn pe_base_relocations_are_available_in_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let optional = 0x98;
    let section_table = optional + 0xf0;
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&6_u32.to_le_bytes());
    bytes[optional + 152..optional + 156].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 156..optional + 160].copy_from_slice(&12_u32.to_le_bytes());
    bytes[section_table..section_table + 6].copy_from_slice(b".reloc");
    bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[0x200..0x204].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[0x204..0x208].copy_from_slice(&12_u32.to_le_bytes());
    bytes[0x208..0x20a].copy_from_slice(&0xa020_u16.to_le_bytes());
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write(
        "relocations.gak",
        &format!("import std.binary\nimport std.formats\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\nprint formats.relocation_count(report)\nprint formats.relocation_summary(report, 0)\nprint formats.relocation_rva(report, 0)\nprint formats.relocation_type(report, 0)\nprint formats.relocation_kind(report, 0)\n"),
    );
    let expected = "1\nDIR64 @ 0x1020\n4128\n10\nDIR64\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);
}

#[test]
fn elf_relocations_are_available_in_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let mut bytes = vec![0_u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&0x80_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0xc4..0xc8].copy_from_slice(&4_u32.to_le_bytes());
    bytes[0xd8..0xe0].copy_from_slice(&0x180_u64.to_le_bytes());
    bytes[0xe0..0xe8].copy_from_slice(&24_u64.to_le_bytes());
    bytes[0xf8..0x100].copy_from_slice(&24_u64.to_le_bytes());
    bytes[0x180..0x188].copy_from_slice(&0x404000_u64.to_le_bytes());
    bytes[0x188..0x190].copy_from_slice(&8_u64.to_le_bytes());
    bytes[0x190..0x198].copy_from_slice(&(-4_i64).to_le_bytes());
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let setup = format!("import std.binary\nimport std.formats\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\n");
    let script = s.write(
        "elf_relocations.gak",
        &format!("{setup}print formats.relocation_count(report)\nprint formats.relocation_location(report)\nprint formats.relocation_summary(report, 0)\nprint formats.relocation_address(report, 0)\nprint formats.relocation_type(report, 0)\nprint formats.relocation_kind(report, 0)\nprint formats.relocation_symbol(report, 0)\nprint formats.relocation_addend(report, 0)\n"),
    );
    let expected =
        "1\nva\nR_X86_64_RELATIVE @ va 0x404000\n0x404000\n8\nR_X86_64_RELATIVE\n0\n-4\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let bad = s.write(
        "elf_rva.gak",
        &format!("{setup}print formats.relocation_rva(report, 0)\n"),
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&bad, engine, false, &[]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("relocation_rva requires a PE image"));
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);
}

#[test]
fn elf_relr_is_available_in_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let mut bytes = vec![0_u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&0x80_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0xc4..0xc8].copy_from_slice(&19_u32.to_le_bytes());
    bytes[0xd8..0xe0].copy_from_slice(&0x180_u64.to_le_bytes());
    bytes[0xe0..0xe8].copy_from_slice(&16_u64.to_le_bytes());
    bytes[0xf8..0x100].copy_from_slice(&8_u64.to_le_bytes());
    bytes[0x180..0x188].copy_from_slice(&0x405000_u64.to_le_bytes());
    bytes[0x188..0x190].copy_from_slice(&0b1011_u64.to_le_bytes());
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let setup = format!("import std.binary\nimport std.formats\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{hex}\")))\n");
    let script = s.write(
        "elf_relr.gak",
        &format!("{setup}print formats.relocation_count(report)\nprint formats.relocation_kind(report, 0)\nprint formats.relocation_summary(report, 1)\nprint formats.relocation_address(report, 2)\n"),
    );
    let expected = "3\nRELR_RELATIVE\nRELR_RELATIVE @ va 0x405008\n0x405018\n";
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&script, engine, false, &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), expected);
    }
    let bad = s.write(
        "elf_relr_type.gak",
        &format!("{setup}print formats.relocation_type(report, 0)\n"),
    );
    for engine in ["ast", "vm"] {
        let out = s.run_engine(&bad, engine, false, &[]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("RELR relocation has no raw type code"));
    }
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), expected);
}

#[test]
fn bounded_for_blocks_work_in_modules_ast_vm_and_bundles() {
    let s = Sandbox::new();
    let helper = s.write("helper.gak", "import std.iter\nimport std.binary\nfn walk(source: Source) -> i64 {\n    for offset in iter.range(binary.size(source)) {\n        impact binary.deep(source, offset, \"u8\")\n    }\n    return binary.size(source)\n}\n");
    let script = s.write("main.gak", "import std.binary\nimport std.iter\nimport helper\nlet source = binary.snapshot(binary.from_hex(\"47 41 47 41\"))\nfor offset in binary.hunt(source, \"GA\") {\n    let found = binary.deep(source, offset, \"u8\")\n    impact found\n}\nfor index in iter.range(2) {\n    for byte in binary.from_hex(\"41 42\") {\n        print index * 10 + byte\n    }\n}\nprint helper.walk(source)\n");
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).contains("65\n66\n75\n76\n"));
    assert!(stdout(&ast).ends_with("4\n"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    fs::remove_file(helper).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&ast), stdout(&compiled));

    let out_of_scope = s.write(
        "scope.gak",
        "import std.iter\nfor index in iter.range(2) {\n    print index\n}\nprint index\n",
    );
    let out = s.run(&out_of_scope, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown name index"),
        "{}",
        stderr(&out)
    );
    let too_large = s.write(
        "limit.gak",
        "import std.iter\nfor index in iter.range(100001) {\n    print index\n}\n",
    );
    let out = s.run(&too_large, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("range exceeds 100000 items"),
        "{}",
        stderr(&out)
    );
    let wrong_type = s.write("wrong.gak", "for item in 42 {\n    print item\n}\n");
    let out = s.run(&wrong_type, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("for expects a List, Offsets, bytes, Disassembly, or Regions"),
        "{}",
        stderr(&out)
    );
    let nested_limit = s.write("nested-limit.gak", "import std.iter\nfor outer in iter.range(11) {\n    for inner in iter.range(100000) {\n    }\n}\n");
    let out = s.run(&nested_limit, false);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution exceeds 1000000 action steps"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn typed_bindings_are_checked_in_source_vm_and_bundles() {
    let s = Sandbox::new();
    let script = s.write(
        "typed.gak",
        "import std.binary\nimport std.asm\nlet source: Source = binary.snapshot(binary.from_hex(\"90 90\"))\nvar total: i64 = 0\nfn scan(source: Source) -> i64 {\n    var offset: i64 = 0\n    while offset < binary.size(source) {\n        let instruction: Instruction = asm.decode(source, offset, 64)\n        offset = asm.next(instruction)\n    }\n    return offset\n}\nprint scan(source)\ntotal = total + 2\nprint total\n",
    );
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), "2\n2\n");
    assert_eq!(stdout(&ast), stdout(&vm));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&compiled), "2\n2\n");

    for (name, program, expected) in [
        ("wrong-global.gak", "let count: i64 = \"bad\"\nprint count\n", "binding count: expected i64, got str"),
        ("wrong-local.gak", "fn value() -> i64 {\n    let count: i64 = \"bad\"\n    return count\n}\nprint value()\n", "binding count: expected i64, got str"),
        ("unknown.gak", "let count: Number = 1\nprint count\n", "unknown type Number"),
        ("late.gak", "print 1\nlet count: i64 = 2\n", "top-level definitions must precede actions"),
    ] {
        let path = s.write(name, program);
        let out = s.run(&path, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(expected), "{name}: {}", stderr(&out));
    }

    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_ok() {
        s.write("dynamic.py", "def wrong():\n    return 'bad'\n");
        let dynamic = s.write("dynamic.gak", "requires { python.exec }\nimport py.dynamic\nlet count: i64 = dynamic.wrong()\nprint count\n");
        let run = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&dynamic)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(!run.status.success());
        assert!(stderr(&run).contains("binding count expects i64"));
        let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("build")
            .arg(&dynamic)
            .output()
            .unwrap();
        assert!(build.status.success(), "{}", stderr(&build));
        let bundle = dynamic.with_extension("gakb");
        fs::remove_file(dynamic).unwrap();
        let exec = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("exec")
            .arg(bundle)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(!exec.status.success());
        assert!(stderr(&exec).contains("binding count expects i64"));

        let local = s.write(
            "dynamic_local.gak",
            "requires { python.exec }\nimport py.dynamic\nfn read() -> i64 {\n    let count: i64 = dynamic.wrong()\n    return count\n}\nprint read()\n",
        );
        let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("build")
            .arg(&local)
            .output()
            .unwrap();
        assert!(build.status.success(), "{}", stderr(&build));
        let bundle = local.with_extension("gakb");
        fs::remove_file(local).unwrap();
        let exec = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("exec")
            .arg(bundle)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(!exec.status.success());
        assert!(stderr(&exec).contains("binding count expects i64"));
    }
}

#[test]
fn asm_entry_decodes_executable_pe_and_elf_bytes_with_provenance() {
    let s = Sandbox::new();
    let section = 0x80 + 4 + 20 + 0xf0;
    let payload = section + 40;
    let mut pe = vec![0_u8; payload + 12];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[0xa8..0xac].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[section..section + 5].copy_from_slice(b".text");
    pe[section + 8..section + 12].copy_from_slice(&7_u32.to_le_bytes());
    pe[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[section + 16..section + 20].copy_from_slice(&7_u32.to_le_bytes());
    pe[section + 20..section + 24].copy_from_slice(&(payload as u32).to_le_bytes());
    pe[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    pe[payload..payload + 5].copy_from_slice(b"\xe8\x02\0\0\0");
    pe[payload + 5..payload + 7].copy_from_slice(b"\x90\x90");

    let mut elf = vec![0_u8; 0x110];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[2, 1, 1]);
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5_u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x401000_u64.to_le_bytes());
    elf[96..104].copy_from_slice(&7_u64.to_le_bytes());
    elf[104..112].copy_from_slice(&7_u64.to_le_bytes());
    elf[0x100..0x105].copy_from_slice(b"\xe8\x02\0\0\0");
    elf[0x105..0x107].copy_from_slice(b"\x90\x90");

    let to_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let script = s.write(
        "entry.gak",
        &format!(
            "import std.binary\nimport std.formats\nimport std.asm\nlet pe: Format = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nlet elf: Format = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nlet pe_instruction: Instruction = asm.entry(pe)\nlet elf_instruction: Instruction = asm.entry(elf)\nprint asm.address(pe_instruction)\nprint asm.target(pe_instruction)\nprint asm.offset(pe_instruction)\nimpact pe_instruction\nprint asm.address(elf_instruction)\nprint asm.target(elf_instruction)\nimpact elf_instruction\n",
            to_hex(&pe),
            to_hex(&elf)
        ),
    );
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    let output = stdout(&ast);
    assert!(output.starts_with(&format!("0x1000\n0x1007\n{payload}\n")));
    assert!(output.contains("PE RVA 0x1000"));
    assert!(output.contains("0x401000\n0x401007\n"));
    assert!(output.contains("ELF VA 0x401000"));
    assert!(output.contains("range: [256..261)"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(output, stdout(&bundled));

    let linear = s.write(
        "linear.gak",
        &format!(
            "import std.binary\nimport std.formats\nimport std.asm\nlet pe: Format = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nlet elf: Format = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nlet pe_lines: Disassembly = asm.linear(pe, 3)\nlet elf_lines: Disassembly = asm.linear(elf, 3)\nlet pe_reach: Disassembly = asm.reachable_entry(pe, 3)\nlet elf_reach: Disassembly = asm.reachable_entry(elf, 3)\nfn collect() -> Disassembly = asm.linear(pe, 3)\nprint asm.count(pe_lines)\nprint asm.target(asm.at(pe_lines, 0))\nfor instruction in pe_lines {{\n    print asm.mnemonic(instruction)\n}}\nprint asm.count(elf_lines)\nfor instruction in elf_lines {{\n    print asm.mnemonic(instruction)\n}}\nprint asm.count(pe_reach)\nprint asm.count(elf_reach)\nimpact pe_lines\n",
            to_hex(&pe),
            to_hex(&elf)
        ),
    );
    let linear_ast = s.run_engine(&linear, "ast", false, &[]);
    let linear_vm = s.run_engine(&linear, "vm", false, &[]);
    assert!(linear_ast.status.success(), "{}", stderr(&linear_ast));
    assert_eq!(stdout(&linear_ast), stdout(&linear_vm));
    let linear_output = stdout(&linear_ast);
    assert!(linear_output.starts_with("3\n0x1007\ncall\nnop\nnop\n3\ncall\nnop\nnop\n"));
    assert!(linear_output.contains("\n3\n3\nimpact"));
    assert!(linear_output.contains("instructions: 3"));
    assert!(linear_output.contains("PE RVA 0x1000"));
    let called = call_json(&linear, "collect", "vm", r#"{"version":1,"args":[]}"#);
    assert!(called.status.success(), "{}", stderr(&called));
    let value: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
    assert_eq!(value["value"]["$galeikan"], "Disassembly");
    assert_eq!(value["value"]["count"], 3);
    assert_eq!(value["value"]["offset"], payload);
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&linear)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = linear.with_extension("gakb");
    fs::remove_file(linear).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(bundle)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(linear_output, stdout(&bundled));

    for (name, expression, expected) in [
        (
            "zero",
            "asm.linear(report, 0)",
            "instruction count must be between 1 and 10000",
        ),
        (
            "overrun",
            "asm.linear(report, 4)",
            "linear disassembly exceeds executable entry region",
        ),
        (
            "index",
            "asm.at(asm.linear(report, 3), 3)",
            "instruction index out of range",
        ),
    ] {
        let script = s.write(
            &format!("linear-{name}.gak"),
            &format!("import std.binary\nimport std.formats\nimport std.asm\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nprint {expression}\n", to_hex(&pe)),
        );
        let out = s.run(&script, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(expected), "{name}: {}", stderr(&out));
    }

    let mut pe32 = pe.clone();
    pe32[0x84..0x86].copy_from_slice(&0x014c_u16.to_le_bytes());
    pe32[0x98..0x9a].copy_from_slice(&0x10b_u16.to_le_bytes());
    let mut elf32 = vec![0_u8; 0x110];
    elf32[0..4].copy_from_slice(b"\x7fELF");
    elf32[4..7].copy_from_slice(&[1, 1, 1]);
    elf32[18..20].copy_from_slice(&3_u16.to_le_bytes());
    elf32[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf32[24..28].copy_from_slice(&0x8048000_u32.to_le_bytes());
    elf32[28..32].copy_from_slice(&52_u32.to_le_bytes());
    elf32[40..42].copy_from_slice(&52_u16.to_le_bytes());
    elf32[42..44].copy_from_slice(&32_u16.to_le_bytes());
    elf32[44..46].copy_from_slice(&1_u16.to_le_bytes());
    elf32[52..56].copy_from_slice(&1_u32.to_le_bytes());
    elf32[56..60].copy_from_slice(&0x100_u32.to_le_bytes());
    elf32[60..64].copy_from_slice(&0x8048000_u32.to_le_bytes());
    elf32[68..72].copy_from_slice(&5_u32.to_le_bytes());
    elf32[72..76].copy_from_slice(&5_u32.to_le_bytes());
    elf32[76..80].copy_from_slice(&5_u32.to_le_bytes());
    elf32[0x100..0x105].copy_from_slice(b"\xe8\x02\0\0\0");
    for (name, bytes, address, target) in [
        ("pe32", pe32, "0x1000", "0x1007"),
        ("elf32", elf32, "0x8048000", "0x8048007"),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!("import std.binary\nimport std.formats\nimport std.asm\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nlet instruction = asm.entry(report)\nprint asm.address(instruction)\nprint asm.target(instruction)\n", to_hex(&bytes)),
        );
        let out = s.run(&script, false);
        assert!(out.status.success(), "{name}: {}", stderr(&out));
        assert_eq!(stdout(&out), format!("{address}\n{target}\n"));
    }

    let mut not_exec_pe = pe.clone();
    not_exec_pe[section + 36..section + 40].copy_from_slice(&0x4000_0040_u32.to_le_bytes());
    let mut wrong_machine = pe.clone();
    wrong_machine[0x84..0x86].copy_from_slice(&0xaa64_u16.to_le_bytes());
    let mut truncated = pe.clone();
    truncated[section + 8..section + 12].copy_from_slice(&1_u32.to_le_bytes());
    truncated[section + 16..section + 20].copy_from_slice(&1_u32.to_le_bytes());
    truncated[payload] = 0x0f;
    let mut not_exec_elf = elf.clone();
    not_exec_elf[68..72].copy_from_slice(&4_u32.to_le_bytes());
    for (name, bytes, expected) in [
        (
            "pe-no-exec",
            not_exec_pe,
            "PE entry section is not executable",
        ),
        (
            "wrong-machine",
            wrong_machine,
            "matching little-endian x86 PE/ELF",
        ),
        (
            "truncated",
            truncated,
            "invalid or truncated x86 instruction",
        ),
        (
            "elf-no-exec",
            not_exec_elf,
            "ELF entry load segment is not executable",
        ),
    ] {
        let script = s.write(
            &format!("{name}.gak"),
            &format!("import std.binary\nimport std.formats\nimport std.asm\nlet report = formats.probe(binary.snapshot(binary.from_hex(\"{}\")))\nprint asm.entry(report)\n", to_hex(&bytes)),
        );
        let out = s.run(&script, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(expected), "{name}: {}", stderr(&out));
    }
}

#[test]
fn x86_instructions_keep_source_context_in_ast_vm_bundles_and_python_calls() {
    let s = Sandbox::new();
    let script = s.write("asm.gak", "import std.binary\nimport std.asm\nfn inspect(data: bytes) -> Instruction = asm.decode(binary.snapshot(data), 0, 4096, 64)\nlet source: Source = binary.snapshot(binary.from_hex(\"90 e8 02 00 00 00 90 90\"))\nlet first: Instruction = asm.decode(source, 0, 64)\nlet branch: Instruction = asm.decode(source, 1, 4096, 64)\nprint asm.text(first)\nprint asm.mnemonic(first)\nprint asm.size(first)\nprint asm.offset(first)\nprint asm.next(first)\nprint binary.size(asm.source(first))\nprint binary.sha256(asm.source(first))\nprint asm.flow(branch)\nprint asm.target(branch)\nprint asm.address(branch)\nprint binary.size(asm.bytes(branch))\nimpact branch\n");
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    let output = stdout(&ast);
    assert!(output.starts_with("nop\nnop\n1\n0\n1\n1\n"));
    assert!(output.contains("\ncall\n0x1007\n0x1000\n5\n"));
    assert!(output.contains("range: [1..6)"));
    assert!(output.contains("view of sha256:"));

    let called = call_json(
        &script,
        "inspect",
        "vm",
        r#"{"version":1,"args":[{"$galeikan":"bytes","hex":"e802000000"}]}"#,
    );
    assert!(called.status.success(), "{}", stderr(&called));
    let value: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
    assert_eq!(value["value"]["$galeikan"], "Instruction");
    assert_eq!(value["value"]["target"], "0x1007");
    assert_eq!(value["value"]["size"], 5);
    assert!(value["value"]["origin"]
        .as_str()
        .unwrap()
        .contains("view of sha256:"));

    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(output, stdout(&compiled));

    for (name, program, expected) in [
        ("invalid.gak", "import std.binary\nimport std.asm\nprint asm.text(asm.decode(binary.snapshot(binary.from_hex(\"0f\")), 0, 64))\n", "invalid or truncated x86 instruction"),
        ("bits.gak", "import std.binary\nimport std.asm\nprint asm.decode(binary.snapshot(binary.from_hex(\"90\")), 0, 8)\n", "x86 bitness must be 16, 32, or 64"),
        ("target.gak", "import std.binary\nimport std.asm\nprint asm.target(asm.decode(binary.snapshot(binary.from_hex(\"90\")), 0, 64))\n", "instruction has no direct branch target"),
        ("offset.gak", "import std.binary\nimport std.asm\nprint asm.decode(binary.snapshot(binary.from_hex(\"90\")), 1, 64)\n", "instruction offset out of bounds"),
    ] {
        let path = s.write(name, program);
        let out = s.run(&path, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(expected), "{name}: {}", stderr(&out));
    }
}

#[test]
fn var_accumulates_across_scopes_and_rejects_immutable_or_wrong_types() {
    let s = Sandbox::new();
    let helper = s.write(
        "helper.gak",
        "var calls = 0\nfn next() -> i64 {\n    calls = calls + 1\n    return calls\n}\n",
    );
    let script = s.write("main.gak", "import std.binary\nimport std.iter\nimport helper\nvar total = 0\nfn score() -> i64 {\n    var sum = 0\n    for index in iter.range(3) {\n        for byte in binary.from_hex(\"01 02\") {\n            sum = sum + index + byte\n        }\n    }\n    return sum\n}\nfor byte in binary.from_hex(\"01 02 03\") {\n    total = total + byte\n}\nprint total\nprint score()\nprint helper.next()\nprint helper.next()\n");
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), "6\n15\n1\n2\n");
    assert_eq!(stdout(&ast), stdout(&vm));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(script).unwrap();
    fs::remove_file(helper).unwrap();
    let compiled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", stderr(&compiled));
    assert_eq!(stdout(&ast), stdout(&compiled));

    for (name, source, expected) in [
        ("fixed.gak", "let fixed = 0\nfixed = 1\n", "cannot assign to immutable binding fixed"),
        ("param.gak", "fn change(n: i64) -> i64 {\n    n = 1\n    return n\n}\nprint change(0)\n", "cannot assign to immutable binding n"),
        ("loop.gak", "import std.iter\nfor index in iter.range(1) {\n    index = 7\n}\n", "cannot assign to immutable binding index"),
        ("type.gak", "var total = 0\ntotal = \"bad\"\n", "assignment to total: expected i64, got str"),
        ("missing.gak", "missing = 1\n", "unknown assignment target missing"),
        ("scope.gak", "import std.iter\nfor index in iter.range(1) {\n    var inner = index\n}\nprint inner\n", "unknown name inner"),
    ] {
        let path = s.write(name, source);
        let out = s.run(&path, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(expected), "{name}: {}", stderr(&out));
    }
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_ok() {
        s.write("dynamic.py", "def text():\n    return 'bad'\n");
        let dynamic = s.write(
            "dynamic.gak",
            "requires { python.exec }\nimport py.dynamic\nvar count = 0\ncount = dynamic.text()\n",
        );
        let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&dynamic)
            .arg("--allow-python")
            .arg(python)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("assignment to count changes runtime type"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn format_signals_work_with_direct_imports_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let mut pe = vec![0_u8; 0x98 + 0xf0];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[0x98 + 70..0x98 + 72].copy_from_slice(&0x0140_u16.to_le_bytes());
    let hex = pe
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write(
        "signals.gak",
        &format!(
            "from std.binary import from_hex, snapshot\nfrom std.formats import probe, signal, field\nlet report: Format = probe(snapshot(from_hex(\"{hex}\")))\nprint signal(report, \"pe.dynamic_base\")\nprint signal(report, \"pe.nx_compat\")\nprint signal(report, \"pe.guard_cf\")\nprint signal(report, \"elf.gnu_relro\")\nimpact field(report, \"dll_characteristics\")\n"
        ),
    );
    let ast = s.run_engine(&script, "ast", false, &[]);
    let vm = s.run_engine(&script, "vm", false, &[]);
    assert!(ast.status.success(), "{}", stderr(&ast));
    assert_eq!(stdout(&ast), stdout(&vm));
    assert!(stdout(&ast).starts_with("present\npresent\nabsent\nnot_applicable\n"));
    assert!(stdout(&ast).contains("range: [222..224), decoder: u16le, value: 320"));
    let build = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let bundled = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("exec")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(bundled.status.success(), "{}", stderr(&bundled));
    assert_eq!(stdout(&ast), stdout(&bundled));
}

#[test]
fn elf_bind_now_audit_preserves_dynamic_flag_field_in_ast_vm_and_bundle() {
    let s = Sandbox::new();
    let mut elf = vec![0_u8; 0x220];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[2, 1, 1]);
    elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&2_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&0x6474_e552_u32.to_le_bytes());
    elf[64 + 40..64 + 48].copy_from_slice(&16_u64.to_le_bytes());
    elf[120..124].copy_from_slice(&2_u32.to_le_bytes());
    elf[120 + 8..120 + 16].copy_from_slice(&0x200_u64.to_le_bytes());
    elf[120 + 32..120 + 40].copy_from_slice(&32_u64.to_le_bytes());
    elf[120 + 40..120 + 48].copy_from_slice(&32_u64.to_le_bytes());
    elf[0x200..0x208].copy_from_slice(&0x6fff_fffb_u64.to_le_bytes());
    elf[0x208..0x210].copy_from_slice(&1_u64.to_le_bytes());
    let hex = elf
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write(
        "relro.gak",
        &format!("requires {{ case.write }}\nfrom std.binary import from_hex, snapshot\nfrom std.formats import probe, signal\nfrom std.audit import signal as assess\nlet report = probe(snapshot(from_hex(\"{hex}\")))\nprint signal(report, \"elf.bind_now\")\nprint signal(report, \"elf.relro_now\")\nimpact assess(report, \"elf.bind_now\", \"present\", \"elf.bind.now\")\nimpact assess(report, \"elf.relro_now\", \"present\", \"elf.relro.now\")\n"),
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let mut baseline = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let case = s.dir.join(format!("relro-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command.arg(mode).arg(if mode == "exec" {
            script.with_extension("gakb")
        } else {
            script.clone()
        });
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with("present\npresent\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let bind = &document["events"][0]["value"];
        assert_eq!(bind["signal"], "elf.bind_now");
        assert_eq!(bind["actual"], "present");
        assert_eq!(bind["field"]["offset"], 0x208);
        assert_eq!(bind["field"]["decoder"], "u64le");
        assert_eq!(bind["field"]["raw_value"], 1);
        assert_eq!(document["events"][1]["value"]["actual"], "present");
        assert!(document["events"][1]["value"]["field"].is_null());
        if let Some(previous) = &baseline {
            assert_eq!(&document["events"], previous);
        }
        baseline = Some(document["events"].clone());
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
    }
}

#[test]
fn pe_section_wx_is_scriptable_and_preserved_in_verified_cases() {
    let s = Sandbox::new();
    let mut pe = vec![0_u8; 0x98 + 0xf0 + 40];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    let flags_offset = 0x98 + 0xf0 + 36;
    pe[flags_offset..flags_offset + 4].copy_from_slice(&0xe000_0020_u32.to_le_bytes());
    let hex = pe
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write(
        "section-wx.gak",
        &format!(
            "requires {{ case.write }}\nfrom std.binary import from_hex, snapshot\nfrom std.formats import probe, section, writable, executable, signal\nfrom std.audit import signal as audit_signal, failed\nlet report = probe(snapshot(from_hex(\"{hex}\")))\nlet target = section(report, 0)\nlet finding = audit_signal(report, \"pe.section_wx\", \"absent\", \"pe.section.wx\")\nprint writable(target)\nprint executable(target)\nprint signal(report, \"pe.section_wx\")\nimpact target\nimpact finding\nprint failed(finding)\n"
        ),
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    let mut baseline = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let case = s.dir.join(format!("section-wx-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command
            .arg(mode)
            .arg(if mode == "exec" { &bundle } else { &script });
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).starts_with("true\ntrue\npresent\n"));
        assert!(stdout(&output)
            .contains("signal: \"pe.section_wx\", expected: \"absent\", actual: present"));
        assert!(stdout(&output).ends_with("true\n") || stdout(&output).ends_with("true\r\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let section = &document["events"][0]["value"];
        assert_eq!(section["writable"], true);
        assert_eq!(section["executable"], true);
        let finding = &document["events"][1]["value"];
        assert_eq!(finding["signal"], "pe.section_wx");
        assert_eq!(finding["passed"], false);
        assert_eq!(finding["field"]["offset"], flags_offset);
        assert_eq!(finding["field"]["raw_value"], 0xe000_0020_u32);
        let verified = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("verify-case")
            .arg(&case)
            .output()
            .unwrap();
        assert!(verified.status.success(), "{}", stderr(&verified));
        if let Some(expected) = &baseline {
            assert_eq!(expected, &document["events"]);
        } else {
            baseline = Some(document["events"].clone());
        }
    }
}

#[test]
fn audit_signal_is_traceable_in_case_bundle_and_python_call() {
    let s = Sandbox::new();
    let mut pe = vec![0_u8; 0x98 + 0xf0];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[0x98 + 70..0x98 + 72].copy_from_slice(&0x0140_u16.to_le_bytes());
    let hex = pe
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script = s.write(
        "signal-audit.gak",
        &format!(
            "requires {{ case.write }}\nfrom std.binary import from_hex, snapshot\nfrom std.formats import probe\nfrom std.audit import signal, passed, failed\nlet report: Format = probe(snapshot(from_hex(\"{hex}\")))\nfn inspect() -> Finding = signal(report, \"pe.nx_compat\", \"present\", \"pe.nx.rule\")\nlet present: Finding = inspect()\nlet missing: Finding = signal(report, \"pe.guard_cf\", \"present\", \"pe.cfg.rule\")\nimpact present\nimpact missing\nprint passed(present)\nprint failed(missing)\n"
        ),
    );
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("build")
        .arg(&script)
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    let bundle = script.with_extension("gakb");
    let mut baseline = None;
    for (mode, engine) in [("run", "ast"), ("run", "vm"), ("exec", "vm")] {
        let case = s.dir.join(format!("signal-{mode}-{engine}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_galeikan"));
        command
            .arg(mode)
            .arg(if mode == "exec" { &bundle } else { &script });
        if mode == "run" {
            command.arg("--engine").arg(engine);
        }
        let output = command.arg("--case").arg(&case).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let printed = stdout(&output);
        assert!(
            printed.contains("signal: \"pe.nx_compat\", expected: \"present\", actual: present")
        );
        assert!(printed.contains("signal: \"pe.guard_cf\", expected: \"present\", actual: absent"));
        assert!(printed.ends_with("true\ntrue\n") || printed.ends_with("true\r\ntrue\r\n"));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&case).unwrap()).unwrap();
        let present = &document["events"][0]["value"];
        let missing = &document["events"][1]["value"];
        assert_eq!(present["kind"], "signal");
        assert_eq!(present["passed"], true);
        assert_eq!(present["signal"], "pe.nx_compat");
        assert_eq!(present["expected"], "present");
        assert_eq!(present["actual"], "present");
        assert_eq!(present["field"]["offset"], 222);
        assert_eq!(present["field"]["raw_value"], 320);
        assert_eq!(present["source_lineage"][0]["operation"], "capture");
        assert_eq!(missing["passed"], false);
        assert_eq!(missing["actual"], "absent");
        if let Some(expected) = &baseline {
            assert_eq!(expected, &document["events"]);
        } else {
            baseline = Some(document["events"].clone());
        }
    }
    for target in [&script, &bundle] {
        let called = call_json(target, "inspect", "vm", r#"{"version":1,"args":[]}"#);
        assert!(called.status.success(), "{}", stderr(&called));
        let body: serde_json::Value = serde_json::from_slice(&called.stdout).unwrap();
        assert_eq!(body["value"]["kind"], "signal");
        assert_eq!(body["value"]["signal"], "pe.nx_compat");
    }
    let mut short_pe = pe.clone();
    short_pe[0x94..0x96].copy_from_slice(&20_u16.to_le_bytes());
    let short_hex = short_pe
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let unavailable = s.write(
        "unavailable.gak",
        &format!("requires {{ case.write }}\nfrom std.binary import from_hex, snapshot\nfrom std.formats import probe\nfrom std.audit import signal\nlet full = probe(snapshot(from_hex(\"{hex}\")))\nlet short = probe(snapshot(from_hex(\"{short_hex}\")))\nimpact signal(full, \"elf.gnu_relro\", \"present\", \"cross.format\")\nimpact signal(short, \"pe.nx_compat\", \"present\", \"missing.field\")\n"),
    );
    let unavailable_case = s.dir.join("unavailable.json");
    let out = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&unavailable)
        .arg("--case")
        .arg(&unavailable_case)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(unavailable_case).unwrap()).unwrap();
    for (index, status) in [(0, "not_applicable"), (1, "unknown")] {
        let finding = &document["events"][index]["value"];
        assert_eq!(finding["passed"], false);
        assert_eq!(finding["actual"], status);
        assert!(finding["field"].is_null());
    }
    for (name, expression, error) in [
        (
            "bad-expect",
            "signal(report, \"pe.nx_compat\", \"unknown\", \"rule\")",
            "signal expectation must be present or absent",
        ),
        (
            "bad-name",
            "signal(report, \"pe.no_such_signal\", \"present\", \"rule\")",
            "unknown format signal",
        ),
        (
            "bad-type",
            "signal(report, 7, \"present\", \"rule\")",
            "expected str, got i64",
        ),
    ] {
        let path = s.write(
            &format!("{name}.gak"),
            &format!("from std.binary import from_hex, snapshot\nfrom std.formats import probe\nfrom std.audit import signal\nlet report = probe(snapshot(from_hex(\"{hex}\")))\nprint {expression}\n"),
        );
        let out = s.run(&path, false);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains(error), "{}", stderr(&out));
    }
}

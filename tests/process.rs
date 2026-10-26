use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct MemoryChild {
    child: Child,
    address: i64,
}

impl MemoryChild {
    fn spawn() -> Option<Self> {
        let python = if cfg!(windows) { "python" } else { "python3" };
        if Command::new(python).arg("--version").output().is_err() {
            return None;
        }
        let source = r#"import ctypes, sys
data = ctypes.create_string_buffer(b'GAK\x00')
if sys.platform.startswith('linux'):
    libc = ctypes.CDLL(None)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    assert libc.prctl(0x59616d61, ctypes.c_ulong(-1).value, 0, 0, 0) == 0
print(ctypes.addressof(data), flush=True)
sys.stdin.read(1)
"#;
        let mut child = Command::new(python)
            .args(["-u", "-c", source])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line
            .trim()
            .parse()
            .expect("helper did not print an address");
        Some(Self { child, address })
    }
}

impl Drop for MemoryChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn process_children_are_typed_sorted_and_permissioned_in_all_engines() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let parent = std::process::id();
    let child = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("galeikan-children-test-{parent}-{id}"));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("children.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\nimport std.process\nfrom std.list import count\n\
             let children: List<i64> = process.children({parent})\n\
             var found = false\nvar sorted = true\nvar previous = 0\n\
             for child in children {{\n    if child == {child} {{\n        found = true\n    }}\n    if child <= previous {{\n        sorted = false\n    }}\n    previous = child\n}}\n\
             print found\nprint sorted\nprint count(process.children({child})) == 0\n"
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let compiled = Command::new(binary)
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args([
                "--engine",
                engine,
                "--allow-process",
                &parent.to_string(),
                "--allow-process",
                &child.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"true\ntrue\ntrue\n");
    }
    let native = Command::new(&executable)
        .args([
            "--allow-process",
            &parent.to_string(),
            "--allow-process",
            &child.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"true\ntrue\ntrue\n");
    for denied in [
        Command::new(binary)
            .arg("run")
            .arg(&script)
            .output()
            .unwrap(),
        Command::new(&executable).output().unwrap(),
    ] {
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_thread_ids_are_typed_permissioned_and_available_in_native_code() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-thread-ids-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("threads.gak");
    fs::write(
        &script,
        "requires { process.inspect }\nimport std.process\nfrom std.list import count\n\
         let ids: List<i64> = process.thread_ids(process.self_pid())\n\
         var sorted = true\nvar previous = 0\n\
         for id in ids {\n    if id <= previous {\n        sorted = false\n    }\n    previous = id\n}\n\
         print count(ids) > 0\nprint sorted\nprint process.executable(process.self_pid()) != \"\"\nprint process.parent_pid(process.self_pid()) == __PARENT__\n"
            .replace("__PARENT__", &std::process::id().to_string()),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let compiled = Command::new(binary)
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", "self"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"true\ntrue\ntrue\ntrue\n");
    }
    let native = Command::new(&executable)
        .args(["--allow-process", "self"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"true\ntrue\ntrue\ntrue\n");
    for denied in [
        Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", "vm"])
            .output()
            .unwrap(),
        Command::new(&executable).output().unwrap(),
    ] {
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_process_snapshot_matches_vm_and_requires_pid_grant() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-native-process-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("snapshot.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\nimport std.process\nimport std.binary\nimport std.bytes\nlet source: Source = process.snapshot({pid}, {}, 4)\nlet unsigned: Source = process.snapshot_u64({pid}, {}u64, 4)\nprint bytes.to_hex(binary.extract(source, 0, 4))\nprint bytes.to_hex(binary.extract(unsigned, 0, 4))\nprint source\n",
            helper.address, helper.address
        ),
    )
    .unwrap();
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable).output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    let denied_self = Command::new(&executable)
        .args(["--allow-process", "self"])
        .output()
        .unwrap();
    assert!(!denied_self.status.success());
    assert!(String::from_utf8_lossy(&denied_self.stderr).contains("process access not allowed"));
    let native = Command::new(&executable)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    assert!(native.stdout.starts_with(b"47414b00\n47414b00\n"));
    let invalid_grant = Command::new(&executable)
        .args(["--allow-process", "0"])
        .output()
        .unwrap();
    assert!(!invalid_grant.status.success());
    assert!(String::from_utf8_lossy(&invalid_grant.stderr).contains("invalid process grant"));
    let undeclared = root.join("undeclared.gak");
    fs::write(
        &undeclared,
        "import std.process\nlet source: Source = process.snapshot(1, 1, 4)\nprint source\n",
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("compile")
        .arg(&undeclared)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("process.inspect"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_process_snapshot_errors_are_catchable() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-native-process-error-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("error.gak");
    fs::write(&script, "requires { process.inspect }\nimport std.process\nfrom std.result import is_error\nfn checked() -> Result<Source> {\n    let source: Source = process.snapshot(process.self_pid(), 1, 4)\n    return source\n}\nprint is_error(checked())\n").unwrap();
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .args(["--allow-process", "self"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"true\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_process_regions_locate_live_memory_and_match_vm() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-native-regions-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("regions.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\nimport std.process\nimport std.binary\nimport std.bytes\nlet regions: Regions = process.regions({pid})\nlet images: Regions = process.images({pid})\nlet region: Region = process.locate_u64(regions, {}u64)\nlet offset: i64 = process.offset_u64(region, {}u64)\nlet reference: str = process.reference(region, {}u64)\nprint process.count(regions) > 0\nprint process.count(images) > 0\nprint process.pid(region) == {pid}\nprint process.start_u64(region) <= {}u64\nprint process.end_u64(region) > {}u64\nprint process.size(region) > 0\nprint process.access(region)\nprint process.image_backed(region)\nprint process.start_u64(process.at(regions, 0)) <= process.end_u64(process.at(regions, 0))\nprint process.address_u64(region, offset) == {}u64\nprint process.resolve(region, reference) == {}u64\nprint reference\nprint region\nprint regions\nfor item in images {{\n    print process.image_backed(item)\n    break\n}}\nprint bytes.to_hex(binary.extract(process.snapshot_region(region, offset, 4), 0, 4))\nprint bytes.to_hex(binary.extract(process.snapshot_at_u64(regions, {}u64, 4), 0, 4))\nprint bytes.to_hex(binary.extract(process.snapshot_ref(region, reference, 4), 0, 4))\nprint process.snapshot_ref(region, reference, 4)\n",
            helper.address, helper.address, helper.address, helper.address, helper.address, helper.address, helper.address, helper.address
        ),
    )
    .unwrap();
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let denied = Command::new(&executable).output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    let native = Command::new(&executable)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    let vm = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("run")
        .arg(&script)
        .args(["--engine", "vm", "--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        vm.status.success(),
        "{}",
        String::from_utf8_lossy(&vm.stderr)
    );
    assert_eq!(native.stdout, vm.stdout);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_process_region_boundary_error_is_catchable() {
    if Command::new("gcc").arg("--version").output().is_err() {
        return;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-native-region-boundary-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("boundary.gak");
    fs::write(&script, "requires { process.inspect }\nimport std.process\nfrom std.result import is_error\nfn checked() -> Result<Source> {\n    let regions: Regions = process.regions(process.self_pid())\n    let region: Region = process.at(regions, 0)\n    return process.snapshot_region(region, process.size(region), 1)\n}\nprint is_error(checked())\n").unwrap();
    let built = Command::new(env!("CARGO_BIN_EXE_galeikan"))
        .arg("compile")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executable = PathBuf::from(String::from_utf8(built.stdout).unwrap().trim());
    let native = Command::new(&executable)
        .args(["--allow-process", "self"])
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"true\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_u64_addresses_can_locate_and_snapshot_memory() {
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-process-u64-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("unsigned.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\nimport std.process\nimport std.binary\nimport std.bytes\nlet regions = process.regions({pid})\nlet address: u64 = {}u64\nlet region = process.locate_u64(regions, address)\nlet reference = process.reference(region, address)\nlet source = process.snapshot_u64({pid}, address, 4)\nlet source_at = process.snapshot_at_u64(regions, process.resolve(region, reference), 4)\nprint process.start_u64(region) <= address\nprint process.end_u64(region) > address\nprint process.address_u64(region, process.offset_u64(region, address)) == address\nprint process.resolve(region, reference) == address\nprint bytes.to_hex(binary.extract(source, 0, 4))\nprint bytes.to_hex(binary.extract(source_at, 0, 4))\n",
            helper.address
        ),
    )
    .unwrap();
    for engine in ["ast", "vm"] {
        let output = Command::new(env!("CARGO_BIN_EXE_galeikan"))
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "true\ntrue\ntrue\ntrue\n47414b00\n47414b00\n"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_snapshot_needs_module_root_and_pid_grants_in_ast_vm_bundle() {
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("galeikan-process-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let module = root.join("collector.gak");
    let script = root.join("main.gak");
    fs::write(
        &module,
        "import std.process\nfn capture(pid: i64, address: i64) -> Source = process.snapshot(pid, address, 4)\n",
    )
    .unwrap();
    let main_source = format!(
        "requires {{ process.inspect }}\nimport collector\nfrom std.binary import deep, size\nlet source = collector.capture({pid}, {})\nimpact deep(source, 0, \"u16le\")\nprint size(source)\n",
        helper.address
    );
    fs::write(&script, &main_source).unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let check = Command::new(binary)
        .arg("check")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("was not declared with requires in"));

    fs::write(
        &module,
        "requires { process.inspect }\nimport std.process\nfn capture(pid: i64, address: i64) -> Source = process.snapshot(pid, address, 4)\n",
    )
    .unwrap();
    let no_grant = root.join("no-grant.gak");
    fs::write(&no_grant, "import collector\nprint 1\n").unwrap();
    let check = Command::new(binary)
        .arg("check")
        .arg(&no_grant)
        .output()
        .unwrap();
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("root script does not grant it"));

    let denied = Command::new(binary)
        .arg("run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("decoder: u16le, value: 16711"), "{stdout}");
        assert!(stdout.contains(&format!("process {pid} @")), "{stdout}");
        assert!(stdout.ends_with("4\n"), "{stdout}");
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
    let bundle: PathBuf = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    fs::remove_file(&module).unwrap();
    let output = Command::new(binary)
        .arg("exec")
        .arg(&bundle)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("value: 16711"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn regions_find_and_snapshot_a_live_allocation_in_ast_vm_bundle() {
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("galeikan-region-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("regions.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\nimport std.process\nimport std.binary\n\
             let regions: Regions = process.regions({pid})\n\
             let region: Region = process.locate(regions, {})\n\
             print process.access(region)\n\
             print process.address(region, process.offset(region, {})) == {}\n\
             impact binary.deep(process.snapshot_at(regions, {}, 4), 0, \"u16le\")\n",
            helper.address, helper.address, helper.address, helper.address
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let denied = Command::new(binary)
        .arg("run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("value: 16711"), "{stdout}");
        assert!(stdout.contains("region"), "{stdout}");
        assert!(stdout.contains("true"), "{stdout}");
    }
    let invalid = root.join("invalid.gaks");
    fs::write(
        &invalid,
        format!(
            "requires {{ process.inspect }}\nfrom std.process import regions, locate, address, size\nlet region = locate(regions({pid}), {})\nprint address(region, size(region))\n",
            helper.address
        ),
    )
    .unwrap();
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&invalid)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("offset is outside process region"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let demo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("process_regions.gak");
    let output = Command::new(binary)
        .arg("run")
        .arg(&demo)
        .args(["--allow-process", &pid.to_string(), "--"])
        .args([pid.to_string(), helper.address.to_string(), "4".into()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("decoder: u8, value: 71"));
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
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let output = Command::new(binary)
        .arg("exec")
        .arg(&bundle)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("value: 16711"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn executable_images_are_permissioned_and_available_in_ast_vm_bundle() {
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("galeikan-image-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("images.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\n\
             from std.process import images, count, at, image_backed, access, label\n\
             let mappings: Regions = images({pid})\n\
             let first: Region = at(mappings, 0)\n\
             print count(mappings)\n\
             print image_backed(first)\n\
             print access(first)\n\
             print label(first)\n"
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let denied = Command::new(binary)
        .arg("run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));

    let mut baseline = None;
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4, "{stdout}");
        assert!(lines[0].parse::<usize>().unwrap() > 0);
        assert_eq!(lines[1], "true");
        assert!(lines[2].ends_with('x'));
        assert!(!lines[3].is_empty());
        if let Some(expected) = &baseline {
            assert_eq!(expected, &stdout);
        } else {
            baseline = Some(stdout);
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
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let output = Command::new(binary)
        .arg("exec")
        .arg(&bundle)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n"),
        baseline.unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_modules_deduplicate_executable_image_paths_in_ast_vm_bundle() {
    let Some(helper) = MemoryChild::spawn() else {
        return;
    };
    let pid = helper.child.id();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "galeikan-module-path-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("modules.gak");
    fs::write(
        &script,
        format!(
            "requires {{ process.inspect }}\n\
             from std.process import modules\n\
             from std.list import count\n\
             let paths: List<str> = modules({pid})\n\
             print count(paths)\n\
             for path in paths {{\n\
                 print path\n\
             }}\n"
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_galeikan");
    let denied = Command::new(binary)
        .arg("run")
        .arg(&script)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("process access not allowed"));

    let check_paths = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
        let lines = stdout.lines().collect::<Vec<_>>();
        let count = lines[0].parse::<usize>().unwrap();
        assert!(count > 0, "{stdout}");
        assert_eq!(count, lines.len() - 1, "{stdout}");
        let mut seen = std::collections::HashSet::new();
        for path in &lines[1..] {
            assert!(!path.is_empty() && *path != "image", "{stdout}");
            let key = if cfg!(windows) {
                path.to_lowercase()
            } else {
                (*path).to_owned()
            };
            assert!(seen.insert(key), "duplicate module path: {stdout}");
        }
    };
    let mut vm_stdout = Vec::new();
    for engine in ["ast", "vm"] {
        let output = Command::new(binary)
            .arg("run")
            .arg(&script)
            .args(["--engine", engine, "--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        check_paths(&output);
        if engine == "vm" {
            vm_stdout = output.stdout;
        }
    }
    if Command::new("gcc").arg("--version").output().is_ok() {
        let compiled = Command::new(binary)
            .arg("compile")
            .arg(&script)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(compiled.stdout).unwrap().trim());
        let native_denied = Command::new(&executable).output().unwrap();
        assert!(!native_denied.status.success());
        assert!(
            String::from_utf8_lossy(&native_denied.stderr).contains("process access not allowed")
        );
        let native = Command::new(&executable)
            .args(["--allow-process", &pid.to_string()])
            .output()
            .unwrap();
        check_paths(&native);
        assert_eq!(native.stdout, vm_stdout);
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
    let bundle = script.with_extension("gakb");
    fs::remove_file(&script).unwrap();
    let output = Command::new(binary)
        .arg("exec")
        .arg(&bundle)
        .args(["--allow-process", &pid.to_string()])
        .output()
        .unwrap();
    check_paths(&output);
    fs::remove_dir_all(root).unwrap();
}

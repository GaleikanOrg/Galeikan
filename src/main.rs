mod asm;
mod bytecode;
mod bytes;
mod case;
mod file_access;
mod formats;
mod native;
mod net;
mod process;
mod project;
mod python_bridge;
mod runtime;
mod syntax;

use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

fn usage() -> &'static str {
    "Usage: galeikan lock <project-dir> | galeikan check <file.gak|file.gaks> | galeikan verify-case <file.json> | galeikan build <file.gak|file.gaks> | galeikan compile <file.gak|file.gaks> | galeikan run <file.gak|file.gaks> [--engine ast|vm] [--case <output.json>] [permissions] [-- <script-args>...] | galeikan exec <file.gakb> [--case <output.json>] [permissions] [-- <script-args>...] | galeikan call <file.gak|file.gaks|file.gakb> <function> [--engine ast|vm] [permissions] [-- <script-args>...] (JSON request on stdin) | galeikan serve <file.gak|file.gaks|file.gakb> [--engine ast|vm] [permissions] [-- <script-args>...] (JSON lines on stdin/stdout)\nPermissions: [--allow-read <directory>]... [--allow-connect <host:port>]... [--allow-process <pid|self>]... [--allow-python <python-executable>]"
}

fn serve(mut session: runtime::CallSession) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = stdout.lock();
    output
        .write_all(b"{\"version\":1,\"ready\":true}\n")
        .and_then(|_| output.flush())
        .map_err(|e| format!("cannot write serve ready message: {e}"))?;
    loop {
        let mut request = Vec::new();
        let count = (&mut input)
            .take((runtime::MAX_CALL_MESSAGE + 2) as u64)
            .read_until(b'\n', &mut request)
            .map_err(|e| format!("cannot read serve request: {e}"))?;
        if count == 0 {
            return Ok(());
        }
        if request.len() > runtime::MAX_CALL_MESSAGE || !request.ends_with(b"\n") {
            return Err("serve request exceeds 1 MiB or has no newline".into());
        }
        let response = session.serve_request(&request);
        output
            .write_all(response.as_bytes())
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .map_err(|e| format!("cannot write serve response: {e}"))?;
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "lock" {
        match project::lock(&PathBuf::from(&args[1])) {
            Ok(path) => println!("{}", path.display()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() == 2 && args[0] == "check" {
        if let Err(error) = runtime::check(&PathBuf::from(&args[1])) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 2 && args[0] == "verify-case" {
        match case::verify(&PathBuf::from(&args[1])) {
            Ok((events, blobs)) => println!("Case verified: {events} events, {blobs} blobs"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() == 2 && args[0] == "build" {
        match runtime::build(&PathBuf::from(&args[1])) {
            Ok(path) => println!("{}", path.display()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() == 2 && args[0] == "compile" {
        match native::compile(&PathBuf::from(&args[1])) {
            Ok(path) => println!("{}", path.display()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() < 2
        || (args[0] != "run" && args[0] != "exec" && args[0] != "call" && args[0] != "serve")
        || (args[0] == "call" && args.len() < 3)
    {
        eprintln!("{}", usage());
        std::process::exit(2);
    }
    let script = PathBuf::from(&args[1]);
    let mut roots = Vec::new();
    let mut allowed_connections = Vec::new();
    let mut allowed_processes = Vec::new();
    let mut python_executable = None;
    let mut case_output = None;
    let mut script_args = Vec::new();
    let is_bundle_call = (args[0] == "call" || args[0] == "serve")
        && script
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("gakb"));
    let mut engine = if is_bundle_call {
        runtime::Engine::Vm
    } else {
        runtime::Engine::Ast
    };
    let mut engine_selected = false;
    let mut i = if args[0] == "call" { 3 } else { 2 };
    while i < args.len() {
        if args[i] == "--" {
            script_args.extend_from_slice(&args[i + 1..]);
            break;
        }
        if (args[0] == "run" || args[0] == "exec")
            && args[i] == "--case"
            && i + 1 < args.len()
            && case_output.is_none()
            && !args[i + 1].is_empty()
        {
            case_output = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        if args[0] != "exec" && args[i] == "--engine" && i + 1 < args.len() && !engine_selected {
            engine = match args[i + 1].as_str() {
                "ast" => runtime::Engine::Ast,
                "vm" => runtime::Engine::Vm,
                _ => {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                }
            };
            engine_selected = true;
            i += 2;
            continue;
        }
        if args[i] == "--allow-python" && i + 1 < args.len() && python_executable.is_none() {
            python_executable = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        if args[i] == "--allow-connect" && i + 1 < args.len() && !args[i + 1].is_empty() {
            allowed_connections.push(args[i + 1].clone());
            i += 2;
            continue;
        }
        if args[i] == "--allow-process" && i + 1 < args.len() {
            if args[i + 1] == "self" {
                allowed_processes.push(std::process::id());
                i += 2;
                continue;
            }
            match args[i + 1].parse::<u32>() {
                Ok(pid) if pid > 0 && pid <= i32::MAX as u32 => {
                    allowed_processes.push(pid);
                    i += 2;
                    continue;
                }
                _ => {
                    eprintln!("invalid process id: {}", args[i + 1]);
                    std::process::exit(2);
                }
            }
        }
        if args[i] != "--allow-read" || i + 1 >= args.len() {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
        match PathBuf::from(&args[i + 1]).canonicalize() {
            Ok(path) if path.is_dir() => roots.push(path),
            _ => {
                eprintln!("invalid read directory: {}", args[i + 1]);
                std::process::exit(2);
            }
        }
        i += 2;
    }
    if args[0] == "call" {
        let mut request = Vec::new();
        if let Err(error) = std::io::stdin()
            .take((runtime::MAX_CALL_MESSAGE + 1) as u64)
            .read_to_end(&mut request)
        {
            eprintln!("cannot read call request: {error}");
            std::process::exit(1);
        }
        match runtime::call(
            &script,
            &args[2],
            &request,
            runtime::CallOptions {
                read_roots: roots,
                allowed_connections,
                allowed_processes,
                python_executable,
                script_args,
                engine,
            },
        ) {
            Ok(response) => println!("{response}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args[0] == "serve" {
        let session = runtime::CallSession::new(
            &script,
            runtime::CallOptions {
                read_roots: roots,
                allowed_connections,
                allowed_processes,
                python_executable,
                script_args,
                engine,
            },
        );
        let result = session.and_then(serve);
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    let options = runtime::RunOptions {
        read_roots: roots,
        allowed_connections,
        allowed_processes,
        python_executable,
        script_args,
        engine,
        case_output,
    };
    let result = if args[0] == "exec" {
        runtime::exec(&script, options)
    } else {
        runtime::run(&script, options)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

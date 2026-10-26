use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

const RUNNER: &str = include_str!("../python/galeikan_bridge/_runner.py");
const MAX_MESSAGE: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct StderrCapture {
    bytes: Vec<u8>,
    overflow: bool,
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Option<(Vec<u8>, bool)>> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some((bytes, true)))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |position| position + 1);
        let room = (MAX_MESSAGE + 1).saturating_sub(bytes.len());
        bytes.extend_from_slice(&available[..count.min(room)]);
        overflow |= count > room;
        reader.consume(count);
        if newline.is_some() {
            return Ok(Some((bytes, overflow)));
        }
    }
}

pub struct Session {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    responses: mpsc::Receiver<io::Result<(Vec<u8>, bool)>>,
    stderr: Arc<Mutex<StderrCapture>>,
    broken: bool,
}

impl Session {
    pub fn start(executable: &Path) -> Result<Self, String> {
        let mut child = Command::new(executable)
            .arg("-I")
            .arg("-B")
            .arg("-c")
            .arg(RUNNER)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start Python: {e}"))?;
        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped Python stdin")));
        let stdout = child.stdout.take().expect("piped Python stdout");
        let mut stderr = child.stderr.take().expect("piped Python stderr");
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_message(&mut reader) {
                    Ok(Some(message)) => {
                        if sender.send(Ok(message)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });
        let captured = Arc::new(Mutex::new(StderrCapture::default()));
        let shared = captured.clone();
        thread::spawn(move || {
            let mut chunk = [0_u8; 8192];
            loop {
                let count = match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => count,
                };
                let mut output = shared.lock().expect("Python stderr capture lock");
                let room = MAX_MESSAGE.saturating_sub(output.bytes.len());
                output.bytes.extend_from_slice(&chunk[..count.min(room)]);
                output.overflow |= count > room;
            }
        });
        Ok(Self {
            child,
            stdin,
            responses,
            stderr: captured,
            broken: false,
        })
    }

    pub fn broken(&self) -> bool {
        self.broken
    }

    pub fn call(
        &mut self,
        module: &Path,
        function: &str,
        args: &[Value],
        expected_sha256: Option<&str>,
    ) -> Result<Value, String> {
        self.request(module, function, "call", args, expected_sha256)
    }

    pub fn get(
        &mut self,
        module: &Path,
        name: &str,
        expected_sha256: Option<&str>,
    ) -> Result<Value, String> {
        self.request(module, name, "get", &[], expected_sha256)
    }

    fn stderr_snapshot(&self) -> String {
        let capture = self.stderr.lock().expect("Python stderr capture lock");
        String::from_utf8_lossy(&capture.bytes).trim().to_owned()
    }

    fn stop(&mut self) {
        self.broken = true;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn request(
        &mut self,
        module: &Path,
        function: &str,
        operation: &str,
        args: &[Value],
        expected_sha256: Option<&str>,
    ) -> Result<Value, String> {
        if self.broken {
            return Err("Python worker is unavailable".into());
        }
        let mut packet = serde_json::to_vec(&json!({
            "path": module.to_string_lossy(),
            "function": function,
            "operation": operation,
            "args": args,
            "expected_sha256": expected_sha256,
        }))
        .map_err(|e| format!("Python request encoding failed: {e}"))?;
        if packet.len() + 1 > MAX_MESSAGE {
            return Err("Python request exceeds 1 MiB".into());
        }
        packet.push(b'\n');
        let stdin = self.stdin.clone();
        let writer = thread::spawn(move || {
            stdin
                .lock()
                .map_err(|_| io::Error::other("Python stdin lock failed"))?
                .write_all(&packet)
        });
        let message = match self.responses.recv_timeout(TIMEOUT) {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => {
                self.stop();
                return Err(format!("Python stdout read failed: {error}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.stop();
                return Err("Python call timed out after 10 seconds".into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.stop();
                return Err(format!("Python process failed: {}", self.stderr_snapshot()));
            }
        };
        let write_result = match writer.join() {
            Ok(result) => result,
            Err(_) => {
                self.stop();
                return Err("Python stdin writer failed".into());
            }
        };
        if let Err(error) = write_result {
            self.stop();
            return Err(format!("Python request write failed: {error}"));
        }
        if message.1 || message.0.len() > MAX_MESSAGE || !message.0.ends_with(b"\n") {
            self.stop();
            return Err("Python output exceeds 1 MiB".into());
        }
        if self
            .stderr
            .lock()
            .expect("Python stderr capture lock")
            .overflow
        {
            self.stop();
            return Err("Python output exceeds 1 MiB".into());
        }
        let response: Value = serde_json::from_slice(&message.0).map_err(|e| {
            self.stop();
            format!("invalid Python bridge response: {e}")
        })?;
        match response.get("ok").and_then(Value::as_bool) {
            Some(true) => match response.get("value") {
                Some(value) => Ok(value.clone()),
                None => {
                    self.stop();
                    Err("Python response has no value".into())
                }
            },
            Some(false) => Err(format!(
                "Python call failed: {}",
                response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
            )),
            None => {
                self.stop();
                Err("invalid Python bridge response".into())
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

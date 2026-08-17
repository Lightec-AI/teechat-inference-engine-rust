//! Bounded `Command::output()` — GPU/SNP tools must not block `--run` forever.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::AttestationError;

pub fn command_output_timed(
    mut cmd: Command,
    timeout: Duration,
    bin: &str,
) -> Result<Output, AttestationError> {
    let timeout_secs = timeout.as_secs().max(1);
    eprintln!("[inference-engine] exec start bin={bin} timeout={timeout_secs}s");
    let started = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| {
            eprintln!("[inference-engine] exec spawn-failed bin={bin} err={source}");
            AttestationError::ToolInvoke {
                bin: bin.to_string(),
                source,
            }
        })?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| AttestationError::ToolInvoke {
            bin: bin.to_string(),
            source: std::io::Error::other("missing stdout pipe"),
        })?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| AttestationError::ToolInvoke {
            bin: bin.to_string(),
            source: std::io::Error::other("missing stderr pipe"),
        })?;
    let t_out = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let t_err = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = t_out.join().unwrap_or_default();
                let stderr = t_err.join().unwrap_or_default();
                let elapsed_ms = started.elapsed().as_millis();
                let code = status.code().unwrap_or(-1);
                eprintln!(
                    "[inference-engine] exec done bin={bin} elapsed_ms={elapsed_ms} status={code}"
                );
                if !status.success() {
                    let tail = String::from_utf8_lossy(&stderr);
                    let tail = tail.trim();
                    if !tail.is_empty() {
                        let tail = if tail.len() > 240 { &tail[..240] } else { tail };
                        eprintln!("[inference-engine] exec stderr bin={bin} {tail}");
                    }
                }
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("[inference-engine] exec timeout bin={bin} after {timeout_secs}s");
                return Err(AttestationError::ToolTimedOut {
                    bin: bin.to_string(),
                    timeout_secs,
                });
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(source) => {
                let _ = child.kill();
                return Err(AttestationError::ToolInvoke {
                    bin: bin.to_string(),
                    source,
                });
            }
        }
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_out_sleep() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = command_output_timed(cmd, Duration::from_secs(1), "sleep").unwrap_err();
        match err {
            AttestationError::ToolTimedOut { bin, timeout_secs } => {
                assert_eq!(bin, "sleep");
                assert_eq!(timeout_secs, 1);
            }
            other => panic!("expected timeout, got {other}"),
        }
    }

    #[test]
    fn captures_true() {
        let cmd = Command::new("true");
        let out = command_output_timed(cmd, Duration::from_secs(5), "true").unwrap();
        assert!(out.status.success());
    }
}

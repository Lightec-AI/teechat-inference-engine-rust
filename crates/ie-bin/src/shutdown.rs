//! Process shutdown signals for the inference-engine binary.
//!
//! systemd `KillSignal=SIGTERM` (see `deploy/systemd/teechat-engine-blue.service`).
//! `tokio::signal::ctrl_c` is SIGINT only — without SIGTERM the process is
//! killed before [`SupervisedPool::close_all`], leaving half-open H2 sessions
//! on the gateway (QEMU user-net hostfwd does not always propagate RST).

use tracing::info;

/// Block until SIGINT (Ctrl+C) or SIGTERM (systemd stop/restart).
pub async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal=SIGINT");
            }
            _ = sigterm.recv() => {
                info!("shutdown signal=SIGTERM");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal=SIGINT");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::wait_shutdown_signal;
    use std::time::Duration;

    #[tokio::test]
    async fn sigterm_unblocks_wait_shutdown_signal() {
        let wait = tokio::spawn(wait_shutdown_signal());
        tokio::time::sleep(Duration::from_millis(80)).await;
        let pid = std::process::id().to_string();
        let status = std::process::Command::new("kill")
            .args(["-s", "TERM", &pid])
            .status()
            .expect("kill");
        assert!(status.success(), "kill -TERM failed: {status}");
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .expect("wait_shutdown_signal did not observe SIGTERM")
            .expect("wait task panicked");
    }
}

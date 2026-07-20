//! Structured stderr event log (port of `ops/event-log.ts`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventLogLevel {
    Debug = 10,
    Info = 20,
    Warn = 30,
    Error = 40,
}

static MIN_LEVEL: OnceLock<Mutex<EventLogLevel>> = OnceLock::new();

fn min_level() -> EventLogLevel {
    *MIN_LEVEL
        .get_or_init(|| Mutex::new(EventLogLevel::Info))
        .lock()
        .expect("event log level")
}

pub fn event_log_level_from_env(env: &HashMap<String, String>) -> EventLogLevel {
    match env
        .get("TEECHAT_LOG_LEVEL")
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("debug") => EventLogLevel::Debug,
        Some("warn") => EventLogLevel::Warn,
        Some("error") => EventLogLevel::Error,
        _ => EventLogLevel::Info,
    }
}

pub fn configure_event_log_from_env(env: &HashMap<String, String>) {
    let level = event_log_level_from_env(env);
    *MIN_LEVEL
        .get_or_init(|| Mutex::new(EventLogLevel::Info))
        .lock()
        .expect("event log level") = level;
}

pub fn log_event(level: EventLogLevel, component: &str, event: &str, fields: &str) {
    if level < min_level() {
        return;
    }
    let level_str = match level {
        EventLogLevel::Debug => "debug",
        EventLogLevel::Info => "info",
        EventLogLevel::Warn => "warn",
        EventLogLevel::Error => "error",
    };
    eprintln!(
        "{{\"level\":\"{level_str}\",\"component\":\"{component}\",\"event\":\"{event}\",\"fields\":{fields}}}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_log_level_from_env_defaults_info() {
        assert_eq!(event_log_level_from_env(&HashMap::new()), EventLogLevel::Info);
    }
}

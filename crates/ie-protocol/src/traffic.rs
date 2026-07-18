//! Traffic class helpers ported from `protocol/types.ts`.

use serde::{Deserialize, Serialize};

pub const OPE_TRAFFIC_CLASS_LIVE_CHAT: &str = "live_chat";
pub const OPE_TRAFFIC_CLASS_API: &str = "api";
pub const DEFAULT_OPE_TRAFFIC_CLASS: &str = OPE_TRAFFIC_CLASS_LIVE_CHAT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpeTrafficClass {
    LiveChat,
    Api,
}

impl OpeTrafficClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveChat => OPE_TRAFFIC_CLASS_LIVE_CHAT,
            Self::Api => OPE_TRAFFIC_CLASS_API,
        }
    }
}

pub fn is_ope_traffic_class(raw: &str) -> bool {
    matches!(raw, OPE_TRAFFIC_CLASS_LIVE_CHAT | OPE_TRAFFIC_CLASS_API)
}

pub fn parse_ope_traffic_class(raw: &str) -> Option<OpeTrafficClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        OPE_TRAFFIC_CLASS_LIVE_CHAT => Some(OpeTrafficClass::LiveChat),
        OPE_TRAFFIC_CLASS_API => Some(OpeTrafficClass::Api),
        _ => None,
    }
}

/// Unknown/missing → `live_chat`. Never invents `api`.
pub fn resolve_ope_traffic_class(raw: Option<&str>) -> OpeTrafficClass {
    raw.and_then(parse_ope_traffic_class)
        .unwrap_or(OpeTrafficClass::LiveChat)
}

pub fn ope_traffic_class_qos_rank(traffic_class: OpeTrafficClass) -> u8 {
    match traffic_class {
        OpeTrafficClass::LiveChat => 0,
        OpeTrafficClass::Api => 1,
    }
}

pub fn should_meter_subscription_usage(traffic_class: OpeTrafficClass) -> bool {
    matches!(traffic_class, OpeTrafficClass::LiveChat)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficClassConsistency {
    Ok { traffic_class: OpeTrafficClass },
    Mismatch { header: OpeTrafficClass, meta: OpeTrafficClass },
    Missing,
}

pub fn traffic_class_header_meta_consistent(
    header_raw: Option<&str>,
    meta_raw: Option<&str>,
) -> TrafficClassConsistency {
    let from_header = header_raw.and_then(parse_ope_traffic_class);
    let from_meta = meta_raw.and_then(parse_ope_traffic_class);
    if let (Some(header), Some(meta)) = (from_header, from_meta) {
        if header != meta {
            return TrafficClassConsistency::Mismatch { header, meta };
        }
    }
    match from_header.or(from_meta) {
        Some(traffic_class) => TrafficClassConsistency::Ok { traffic_class },
        None => TrafficClassConsistency::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_live_chat() {
        assert_eq!(
            resolve_ope_traffic_class(None),
            OpeTrafficClass::LiveChat
        );
        assert_eq!(
            resolve_ope_traffic_class(Some("unknown")),
            OpeTrafficClass::LiveChat
        );
    }

    #[test]
    fn header_meta_mismatch() {
        let result = traffic_class_header_meta_consistent(Some("live_chat"), Some("api"));
        assert!(matches!(
            result,
            TrafficClassConsistency::Mismatch { .. }
        ));
    }
}

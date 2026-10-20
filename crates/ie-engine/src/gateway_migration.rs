//! Gateway plane migration planning (port of `engine/gateway-migration.ts`).

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayMigrationPlan {
    pub target_count: u32,
    pub to_move: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct GatewayMigrationRequest {
    pub target_url: String,
    pub fraction: f64,
}

/// Sessions that must sit on the migration target. Idle count is not an input:
/// busy chats stay on the source until they finish, and the caller dials
/// replacements onto the target immediately.
pub fn plan_gateway_migration(
    pool_size: u32,
    on_target: u32,
    fraction: f64,
) -> GatewayMigrationPlan {
    if pool_size < 1 {
        return GatewayMigrationPlan {
            target_count: 0,
            to_move: 0,
            blocked: true,
            reason: Some("pool_size_zero".into()),
        };
    }
    if !(0.0..=1.0).contains(&fraction) {
        return GatewayMigrationPlan {
            target_count: 0,
            to_move: 0,
            blocked: true,
            reason: Some("invalid_fraction".into()),
        };
    }
    let target_count = ((pool_size as f64) * fraction).floor() as u32;
    GatewayMigrationPlan {
        target_count,
        to_move: target_count.saturating_sub(on_target),
        blocked: false,
        reason: None,
    }
}

pub fn parse_gateway_migration_request_json(raw: &str) -> Result<GatewayMigrationRequest, String> {
    let parsed: GatewayMigrationRequest = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let target = parsed.target_url.trim();
    if target.is_empty() {
        return Err("gateway migration: target_url required".into());
    }
    if !(0.0..=1.0).contains(&parsed.fraction) {
        return Err("gateway migration: fraction must be 0..1".into());
    }
    Ok(GatewayMigrationRequest {
        target_url: target.to_string(),
        fraction: parsed.fraction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_gateway_migration_half_of_four() {
        let plan = plan_gateway_migration(4, 0, 0.5);
        assert_eq!(plan.target_count, 2);
        assert_eq!(plan.to_move, 2);
        assert!(!plan.blocked);
        assert!(plan.reason.is_none());
    }

    #[test]
    fn plan_gateway_migration_does_not_require_idle_sessions() {
        let plan = plan_gateway_migration(4, 0, 1.0);
        assert_eq!(plan.to_move, 4);
        assert!(!plan.blocked);
    }

    #[test]
    fn plan_gateway_migration_counts_sessions_already_on_target() {
        let plan = plan_gateway_migration(4, 2, 0.5);
        assert_eq!(plan.to_move, 0);
        assert!(!plan.blocked);
    }
}

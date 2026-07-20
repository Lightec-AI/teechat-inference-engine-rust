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

pub fn plan_gateway_migration(
    pool_size: u32,
    on_target: u32,
    fraction: f64,
    idle_on_source: u32,
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
    let need = target_count.saturating_sub(on_target);
    if need == 0 {
        return GatewayMigrationPlan {
            target_count,
            to_move: 0,
            blocked: false,
            reason: None,
        };
    }
    if idle_on_source < need {
        return GatewayMigrationPlan {
            target_count,
            to_move: idle_on_source,
            blocked: true,
            reason: Some("insufficient_idle_sessions".into()),
        };
    }
    GatewayMigrationPlan {
        target_count,
        to_move: need,
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
    fn plan_gateway_migration_moves_idle_sessions() {
        let plan = plan_gateway_migration(4, 0, 0.5, 4);
        assert_eq!(plan.target_count, 2);
        assert_eq!(plan.to_move, 2);
        assert!(!plan.blocked);
    }

    #[test]
    fn plan_gateway_migration_blocks_when_idle_insufficient() {
        let plan = plan_gateway_migration(4, 0, 1.0, 2);
        assert_eq!(plan.to_move, 2);
        assert!(plan.blocked);
    }
}

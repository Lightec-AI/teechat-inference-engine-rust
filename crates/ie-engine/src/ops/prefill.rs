//! KV prefill planning (port of `prefill.ts`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationKvState {
    pub prefix_hash: String,
    pub prefilled_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefillPlan {
    pub warm_prefix_tokens: u64,
    pub cold_suffix_tokens: u64,
}

pub fn plan_vllm_prefill(
    state: Option<&ConversationKvState>,
    prompt_token_count: u64,
    prefix_hash: &str,
) -> (PrefillPlan, ConversationKvState) {
    let tokens = prompt_token_count;
    if state.is_none_or(|s| s.prefix_hash != prefix_hash) {
        return (
            PrefillPlan {
                warm_prefix_tokens: 0,
                cold_suffix_tokens: tokens,
            },
            ConversationKvState {
                prefix_hash: prefix_hash.to_string(),
                prefilled_tokens: tokens,
            },
        );
    }
    let state = state.expect("checked");
    let warm = state.prefilled_tokens.min(tokens);
    let cold = tokens - warm;
    (
        PrefillPlan {
            warm_prefix_tokens: warm,
            cold_suffix_tokens: cold,
        },
        ConversationKvState {
            prefix_hash: prefix_hash.to_string(),
            prefilled_tokens: tokens,
        },
    )
}

pub fn conversation_kv_key(conversation_id: &str, model: &str) -> String {
    format!("{conversation_id}\0{model}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_vllm_prefill_cold_on_new_prefix() {
        let (plan, next) = plan_vllm_prefill(None, 10, "h1");
        assert_eq!(plan.warm_prefix_tokens, 0);
        assert_eq!(plan.cold_suffix_tokens, 10);
        assert_eq!(next.prefilled_tokens, 10);
    }

    #[test]
    fn plan_vllm_prefill_warm_on_same_prefix() {
        let state = ConversationKvState {
            prefix_hash: "h1".into(),
            prefilled_tokens: 8,
        };
        let (plan, _) = plan_vllm_prefill(Some(&state), 10, "h1");
        assert_eq!(plan.warm_prefix_tokens, 8);
        assert_eq!(plan.cold_suffix_tokens, 2);
    }
}

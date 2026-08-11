//! Policy model and the central decision function.
//!
//! Precedence (most restrictive wins):
//!   deny > ask > auto
//!
//! Sources, in the order they are combined:
//!   1. the vault item's `agent-policy` custom field, else the global default
//!   2. a "remember" rule in the broker DB may lift `ask` -> `auto`
//!   3. the agent token's optional `max_policy` caps the result

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Auto,
    Ask,
    Deny,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "allow" => Some(Policy::Auto),
            "ask" | "prompt" => Some(Policy::Ask),
            "deny" | "block" | "never" => Some(Policy::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::Auto => "auto",
            Policy::Ask => "ask",
            Policy::Deny => "deny",
        }
    }

    /// Higher rank == more restrictive.
    fn rank(&self) -> u8 {
        match self {
            Policy::Auto => 0,
            Policy::Ask => 1,
            Policy::Deny => 2,
        }
    }

    /// The more restrictive of the two.
    pub fn tighter(self, other: Policy) -> Policy {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inputs of a single access decision.
pub struct Decision {
    /// `agent-policy` custom field of the vault item, if present and valid.
    pub item_policy: Option<Policy>,
    /// Global fallback from config.
    pub default_policy: Policy,
    /// Cap configured on the agent token (`max_policy`), if any.
    pub token_max: Option<Policy>,
    /// An active remember-rule exists for this (item, token) pair.
    pub remembered: bool,
}

/// Resolve the effective policy for one credential access.
pub fn decide(d: &Decision) -> Policy {
    let base = d.item_policy.unwrap_or(d.default_policy);

    // "deny gewinnt immer" - neither a remember rule nor anything else lifts it.
    if base == Policy::Deny {
        return Policy::Deny;
    }
    if d.token_max == Some(Policy::Deny) {
        return Policy::Deny;
    }

    // A remember rule may turn ask into auto ...
    let mut eff = base;
    if eff == Policy::Ask && d.remembered {
        eff = Policy::Auto;
    }

    // ... but the token cap is applied afterwards and can pull it back to ask.
    if let Some(max) = d.token_max {
        eff = eff.tighter(max);
    }
    eff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Decision {
        Decision {
            item_policy: None,
            default_policy: Policy::Ask,
            token_max: None,
            remembered: false,
        }
    }

    #[test]
    fn item_field_overrides_default_and_deny_always_wins() {
        // auto field -> immediate delivery
        let d = Decision {
            item_policy: Some(Policy::Auto),
            ..base()
        };
        assert_eq!(decide(&d), Policy::Auto);

        // no field -> global default
        assert_eq!(decide(&base()), Policy::Ask);
        let d = Decision {
            default_policy: Policy::Auto,
            ..base()
        };
        assert_eq!(decide(&d), Policy::Auto);

        // deny beats everything, even a remember rule and an auto default
        let d = Decision {
            item_policy: Some(Policy::Deny),
            default_policy: Policy::Auto,
            token_max: Some(Policy::Auto),
            remembered: true,
        };
        assert_eq!(decide(&d), Policy::Deny);
    }

    #[test]
    fn remember_rule_lifts_ask_to_auto_but_not_deny() {
        let d = Decision {
            item_policy: Some(Policy::Ask),
            remembered: true,
            ..base()
        };
        assert_eq!(decide(&d), Policy::Auto);

        // ... only while the rule is active
        let d = Decision {
            item_policy: Some(Policy::Ask),
            remembered: false,
            ..base()
        };
        assert_eq!(decide(&d), Policy::Ask);

        // remember rule must never resurrect a denied item
        let d = Decision {
            item_policy: Some(Policy::Deny),
            remembered: true,
            ..base()
        };
        assert_eq!(decide(&d), Policy::Deny);
    }

    #[test]
    fn token_max_policy_caps_the_result() {
        // token may never get "auto": auto item is downgraded to ask
        let d = Decision {
            item_policy: Some(Policy::Auto),
            token_max: Some(Policy::Ask),
            ..base()
        };
        assert_eq!(decide(&d), Policy::Ask);

        // ... and a remember rule cannot bypass that cap either
        let d = Decision {
            item_policy: Some(Policy::Ask),
            token_max: Some(Policy::Ask),
            remembered: true,
            ..base()
        };
        assert_eq!(decide(&d), Policy::Ask);

        // max_policy = deny locks the token out completely
        let d = Decision {
            item_policy: Some(Policy::Auto),
            token_max: Some(Policy::Deny),
            ..base()
        };
        assert_eq!(decide(&d), Policy::Deny);

        // a permissive cap never loosens the item policy
        let d = Decision {
            item_policy: Some(Policy::Ask),
            token_max: Some(Policy::Auto),
            ..base()
        };
        assert_eq!(decide(&d), Policy::Ask);
    }

    #[test]
    fn policy_parsing_is_lenient_but_closed() {
        assert_eq!(Policy::parse(" AUTO "), Some(Policy::Auto));
        assert_eq!(Policy::parse("Ask"), Some(Policy::Ask));
        assert_eq!(Policy::parse("deny"), Some(Policy::Deny));
        assert_eq!(Policy::parse("vielleicht"), None);
        // an unparsable field value must not silently become "auto";
        // callers treat None as "field absent" -> default policy applies
        assert_eq!(Policy::Auto.tighter(Policy::Deny), Policy::Deny);
        assert_eq!(Policy::Ask.tighter(Policy::Auto), Policy::Ask);
    }
}

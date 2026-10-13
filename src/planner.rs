//! Mitigation planner.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationPlan {
    pub immediate: Action,
    pub medium_term: Option<Action>,
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    pub rationale: String,
    pub effort: String,
    pub hours: u32,
}

pub fn plan_for(has_cve: bool, has_patch: bool, pony: Option<u32>) -> MitigationPlan {
    let (immediate, medium_term) = match (has_cve, has_patch, pony) {
        (true, true, _) => (
            Action {
                action: "bump_version".into(),
                rationale: "Patch available".into(),
                effort: "low".into(),
                hours: 2,
            },
            None,
        ),
        (true, false, Some(1)) => (
            Action {
                action: "replace_crate".into(),
                rationale: "No patch + solo maintainer".into(),
                effort: "high".into(),
                hours: 40,
            },
            Some(Action {
                action: "fork_and_hotfix".into(),
                rationale: "Interim while migrating".into(),
                effort: "high".into(),
                hours: 24,
            }),
        ),
        (true, false, _) => (
            Action {
                action: "fork_hotfix".into(),
                rationale: "No patch upstream".into(),
                effort: "high".into(),
                hours: 32,
            },
            None,
        ),
        (false, _, Some(1)) => (
            Action {
                action: "find_co_maintainer".into(),
                rationale: "Solo maintainer risk".into(),
                effort: "medium".into(),
                hours: 8,
            },
            None,
        ),
        _ => (
            Action {
                action: "monitor".into(),
                rationale: "Low risk".into(),
                effort: "low".into(),
                hours: 1,
            },
            None,
        ),
    };
    MitigationPlan {
        immediate,
        medium_term,
        alternatives: vec![],
    }
}

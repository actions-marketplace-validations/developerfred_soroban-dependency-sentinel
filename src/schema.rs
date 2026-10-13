//! JSON Schema for the `DependencyReport` output.
//!
//! Hand-written to avoid an extra dependency. Emitted by `sentinel schema`.

use serde_json::{json, Value};

/// Returns a JSON Schema (draft 2020-12) describing `Vec<DependencyReport>`.
pub fn dependency_report_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://developerfred.github.io/soroban-dependency-sentinel/schemas/dependency-report.json",
        "title": "Soroban Dependency Sentinel — DependencyReport",
        "type": "array",
        "items": {
            "type": "object",
            "required": [
                "crate_name", "version", "vulnerabilities",
                "pony_source", "risk_score", "classification"
            ],
            "properties": {
                "crate_name": { "type": "string", "minLength": 1 },
                "version": { "type": "string", "minLength": 1 },
                "vulnerabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "summary", "severity"],
                        "properties": {
                            "id": { "type": "string", "minLength": 1 },
                            "summary": { "type": "string" },
                            "severity": { "type": "string" },
                            "patched_versions": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    }
                },
                "pony_factor": { "type": ["integer", "null"], "minimum": 0 },
                "pony_source": {
                    "type": "string",
                    "enum": ["pg_atlas", "crates_io_owners", "local_fallback", "unknown"]
                },
                "risk_score": { "type": "number", "minimum": 0.0 },
                "classification": {
                    "type": "string",
                    "enum": ["safe", "watch", "high", "critical"]
                },
                "mitigation": {
                    "type": ["object", "null"],
                    "required": ["immediate"],
                    "properties": {
                        "immediate": { "$ref": "#/$defs/action" },
                        "medium_term": { "anyOf": [{ "$ref": "#/$defs/action" }, { "type": "null" }] },
                        "alternatives": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                }
            }
        },
        "$defs": {
            "action": {
                "type": "object",
                "required": ["action", "rationale", "effort", "hours"],
                "properties": {
                    "action": { "type": "string" },
                    "rationale": { "type": "string" },
                    "effort": { "type": "string", "enum": ["low", "medium", "high"] },
                    "hours": { "type": "integer", "minimum": 0 }
                }
            }
        }
    })
}

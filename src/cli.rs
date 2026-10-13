use crate::reporter::{self, ScanOptions};
use crate::scorer::Classification;
use crate::{baseline, config::Config, markdown, plugins, report_html, schema};
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sentinel", version, about = "Soroban supply-chain scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Scan a project directory for vulnerable/dangerous dependencies.
    Scan {
        #[arg(long, default_value = ".")]
        path: PathBuf,

        #[arg(long, default_value = "json",
              value_parser = ["json", "sarif", "markdown", "text", "html"])]
        format: String,

        #[arg(long, default_value_t = false)]
        deep_pony: bool,

        #[arg(long, default_value_t = false)]
        include_local: bool,

        #[arg(long, default_value_t = false)]
        offline: bool,

        /// Disable plugin discovery and execution.
        #[arg(long, default_value_t = false)]
        no_plugins: bool,

        #[arg(long)]
        baseline: Option<PathBuf>,

        #[arg(long, value_enum)]
        fail_on: Option<FailLevel>,
    },

    /// Explain an advisory ID (e.g. RUSTSEC-2020-0071) via OSV.dev.
    Explain {
        /// Advisory ID.
        id: String,
    },

    /// Interactive setup: writes sentinel.toml and a GitHub Action workflow.
    Wizard {
        #[arg(long, default_value = ".")]
        path: PathBuf,

        #[arg(long, default_value_t = false)]
        yes: bool,
    },

    /// Emit the JSON Schema of the scan output (draft 2020-12).
    Schema,

    /// List installed `sentinel-plugin-*` executables.
    Plugins,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailLevel {
    None,
    Watch,
    High,
    Critical,
}

impl FailLevel {
    fn rank(self) -> u8 {
        match self {
            FailLevel::None => u8::MAX,
            FailLevel::Watch => 1,
            FailLevel::High => 2,
            FailLevel::Critical => 3,
        }
    }
}

fn parse_fail_level(s: &str) -> FailLevel {
    match s.to_ascii_lowercase().as_str() {
        "watch" => FailLevel::Watch,
        "high" => FailLevel::High,
        "critical" => FailLevel::Critical,
        _ => FailLevel::None,
    }
}

fn class_rank(c: Classification) -> u8 {
    match c {
        Classification::Safe => 0,
        Classification::Watch => 1,
        Classification::High => 2,
        Classification::Critical => 3,
    }
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Scan {
            path,
            format,
            deep_pony,
            include_local,
            offline,
            no_plugins,
            baseline,
            fail_on,
        } => {
            let opts = ScanOptions {
                deep_pony,
                include_local,
                offline,
                no_plugins,
            };
            let report = reporter::scan_project_with(&path, opts)?;

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&report)?),
                "sarif" => println!(
                    "{}",
                    serde_json::to_string_pretty(&reporter::to_sarif(&report))?
                ),
                "markdown" => print!("{}", markdown::render(&report)),
                "html" => print!("{}", report_html::render(&report)),
                _ => reporter::print_text(&report),
            }

            if let Some(baseline_path) = baseline {
                let base = baseline::load(&baseline_path)?;
                let regs = baseline::diff(&report, &base);
                if !regs.is_empty() {
                    let ids: Vec<&str> = regs.iter().map(|r| r.crate_name.as_str()).collect();
                    anyhow::bail!(
                        "baseline regressions detected in {} crate(s): {:?}",
                        regs.len(),
                        ids
                    );
                }
                return Ok(());
            }

            let cfg = Config::load(&path).unwrap_or_default();
            let level = fail_on.unwrap_or_else(|| parse_fail_level(&cfg.scan.fail_on));
            let threshold = level.rank();

            let worst = report
                .iter()
                .map(|r| class_rank(r.classification))
                .max()
                .unwrap_or(0);

            if worst >= threshold {
                anyhow::bail!(
                    "risk gate: worst classification rank {worst} >= threshold {threshold}"
                );
            }
            Ok(())
        }

        Cmd::Explain { id } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(reporter::explain_advisory(&id))
        }

        Cmd::Wizard { path, yes } => crate::wizard::run(&path, yes),

        Cmd::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&schema::dependency_report_schema())?
            );
            Ok(())
        }

        Cmd::Plugins => {
            let discovered = plugins::discover();
            if discovered.is_empty() {
                println!("(no sentinel-plugin-* executables found in PATH)");
            } else {
                println!("{:<20} PATH", "NAME");
                for p in discovered {
                    println!("{:<20} {}", p.name, p.path.display());
                }
            }
            Ok(())
        }
    }
}

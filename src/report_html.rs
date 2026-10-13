//! Self-contained HTML report (no external assets, opens in a browser).

use crate::scorer::Classification;
use crate::DependencyReport;

fn class_color(c: Classification) -> &'static str {
    match c {
        Classification::Safe => "#16a34a",
        Classification::Watch => "#eab308",
        Classification::High => "#f97316",
        Classification::Critical => "#dc2626",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render a full standalone HTML document.
pub fn render(reports: &[DependencyReport]) -> String {
    let total = reports.len();
    let with_cve = reports
        .iter()
        .filter(|r| !r.vulnerabilities.is_empty())
        .count();
    let high_crit = reports
        .iter()
        .filter(|r| {
            matches!(
                r.classification,
                Classification::High | Classification::Critical
            )
        })
        .count();

    let mut rows = String::new();
    for r in reports {
        let cve_list = if r.vulnerabilities.is_empty() {
            "—".to_string()
        } else {
            r.vulnerabilities
                .iter()
                .map(|v| {
                    format!(
                        "<a href=\"https://osv.dev/vulnerability/{}\" target=\"_blank\">{}</a>",
                        esc(&v.id),
                        esc(&v.id)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mitigation = match &r.mitigation {
            Some(m) => format!(
                "<details><summary>{}</summary><p><b>Rationale:</b> {}<br><b>Effort:</b> {} ({}h)</p></details>",
                esc(&m.immediate.action),
                esc(&m.immediate.rationale),
                esc(&m.immediate.effort),
                m.immediate.hours
            ),
            None => "—".into(),
        };

        rows.push_str(&format!(
            r#"<tr>
  <td><code>{name}</code></td>
  <td><code>{version}</code></td>
  <td style="color:{color};font-weight:600">{score:.2}</td>
  <td><span class="badge" style="background:{color}">{class:?}</span></td>
  <td>{pony}</td>
  <td><small>{source:?}</small></td>
  <td>{cves}</td>
  <td>{mit}</td>
</tr>"#,
            name = esc(&r.crate_name),
            version = esc(&r.version),
            color = class_color(r.classification),
            score = r.risk_score,
            class = r.classification,
            pony = r
                .pony_factor
                .map(|p| p.to_string())
                .unwrap_or_else(|| "—".into()),
            source = r.pony_source,
            cves = cve_list,
            mit = mitigation,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Soroban Dependency Sentinel — Report</title>
<style>
  :root {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ margin: 2rem; color: #111; background: #fafafa; }}
  h1 {{ margin: 0 0 0.25rem; }}
  .meta {{ color: #555; margin-bottom: 1.5rem; }}
  .stats {{ display: flex; gap: 2rem; margin-bottom: 1.5rem; }}
  .stat {{ background: #fff; border: 1px solid #e5e5e5; border-radius: 6px; padding: 0.75rem 1rem; }}
  .stat b {{ display: block; font-size: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #eee; vertical-align: top; }}
  th {{ background: #f4f4f5; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; color: #555; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ color: #fff; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }}
  a {{ color: #2563eb; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  details summary {{ cursor: pointer; font-weight: 600; }}
  footer {{ margin-top: 2rem; color: #888; font-size: 0.85rem; }}
</style>
</head>
<body>
  <h1>🛡️ Soroban Dependency Sentinel</h1>
  <p class="meta">Generated {when}</p>
  <div class="stats">
    <div class="stat"><b>{total}</b>dependencies</div>
    <div class="stat"><b>{cves}</b>with advisories</div>
    <div class="stat"><b>{high}</b>high/critical</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Crate</th><th>Version</th><th>Score</th><th>Class</th>
        <th>Pony</th><th>Source</th><th>Advisories</th><th>Mitigation</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <footer>
    <a href="https://github.com/{repo}">soroban-dependency-sentinel</a> · Apache-2.0
  </footer>
</body>
</html>
"#,
        when = chrono::Utc::now().to_rfc3339(),
        total = total,
        cves = with_cve,
        high = high_crit,
        rows = rows,
        repo = "developerfred/soroban-dependency-sentinel",
    )
}

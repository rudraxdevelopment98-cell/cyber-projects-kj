"""Report generation for the AWS Security Audit tool.

Turns a list of findings into:
  * a risk score and severity breakdown (the executive summary), and
  * a self-contained HTML report rendered with Jinja2.
"""

from collections import Counter, OrderedDict
from datetime import datetime, timezone

from jinja2 import Template

from checks.finding import SEVERITY_WEIGHTS

# Severity render order (worst first) used in tables and summaries.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def summarise(findings):
    """Compute the executive summary metrics from a list of findings.

    The risk score is a 0-100 scale where 0 = clean. We sum the severity
    weights of all FAIL findings and cap at 100 so the headline number stays
    interpretable on the report.
    """
    fails = [f for f in findings if f.get("status", "FAIL") == "FAIL"]
    counts = Counter(f["severity"] for f in fails)
    raw_score = sum(SEVERITY_WEIGHTS[f["severity"]] for f in fails)
    risk_score = min(raw_score, 100)

    if counts.get("Critical"):
        posture = "Critical - immediate remediation required"
    elif counts.get("High"):
        posture = "Poor - high-risk gaps present"
    elif counts.get("Medium"):
        posture = "Fair - hardening recommended"
    elif fails:
        posture = "Good - minor issues only"
    else:
        posture = "Strong - no misconfigurations detected"

    breakdown = OrderedDict((sev, counts.get(sev, 0)) for sev in SEVERITY_ORDER)
    return {
        "risk_score": risk_score,
        "total_findings": len(fails),
        "severity_breakdown": breakdown,
        "posture": posture,
    }


def framework_matrix(findings):
    """Aggregate how many findings touch each framework control."""
    matrix = Counter()
    for f in findings:
        for ctrl in [c.strip() for c in f["framework_mapping"].split("/")]:
            matrix[ctrl] += 1
    return OrderedDict(sorted(matrix.items()))


_HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AWS Security Audit Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; color: #1a1a2e; background: #f5f6fa; }
  header { background: #16213e; color: #fff; padding: 32px 40px; }
  header h1 { margin: 0 0 4px; font-size: 24px; }
  header .meta { color: #9aa7c7; font-size: 13px; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px 40px 60px; }
  .cards { display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }
  .card { background: #fff; border-radius: 10px; padding: 18px 22px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .big { font-size: 30px; font-weight: 700; }
  .score-Critical, .sev-Critical { color: #c0392b; }
  .score-High, .sev-High { color: #e67e22; }
  .sev-Medium { color: #d4ac0d; }
  .sev-Low { color: #2980b9; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 13px; vertical-align: top; }
  th { background: #16213e; color: #fff; font-weight: 600; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #fff; }
  .pill-Critical { background: #c0392b; } .pill-High { background: #e67e22; }
  .pill-Medium { background: #d4ac0d; } .pill-Low { background: #2980b9; } .pill-Info { background: #7f8c8d; }
  h2 { margin-top: 40px; border-bottom: 2px solid #16213e; padding-bottom: 6px; }
  code { background: #eef; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .rem { color: #555; }
</style>
</head>
<body>
<header>
  <h1>AWS Security Misconfiguration Audit Report</h1>
  <div class="meta">Account: {{ account }} &nbsp;|&nbsp; Generated: {{ generated }} &nbsp;|&nbsp; Tool: aws-audit by Kuldeep J. Jotaniya</div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div>Risk Score</div><div class="big score-{{ '%s' % ('Critical' if summary.risk_score>=60 else 'High') }}">{{ summary.risk_score }}/100</div></div>
    <div class="card"><div>Total Findings</div><div class="big">{{ summary.total_findings }}</div></div>
    <div class="card"><div>Posture</div><div style="font-weight:700;margin-top:6px">{{ summary.posture }}</div></div>
  </div>

  <div class="cards">
    {% for sev, n in summary.severity_breakdown.items() %}
    <div class="card"><div class="sev-{{ sev }}">{{ sev }}</div><div class="big sev-{{ sev }}">{{ n }}</div></div>
    {% endfor %}
  </div>

  <h2>Findings</h2>
  <table>
    <tr><th>ID</th><th>Severity</th><th>Finding</th><th>Resource</th><th>Framework</th><th>Remediation</th></tr>
    {% for f in findings %}
    <tr>
      <td><code>{{ f.check_id }}</code></td>
      <td><span class="pill pill-{{ f.severity }}">{{ f.severity }}</span></td>
      <td><strong>{{ f.name }}</strong><br><span class="rem">{{ f.description }}</span></td>
      <td><code>{{ f.resource }}</code></td>
      <td>{{ f.framework_mapping }}</td>
      <td class="rem">{{ f.remediation }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Framework Coverage Matrix</h2>
  <table>
    <tr><th>Control</th><th>Findings Mapped</th></tr>
    {% for ctrl, n in matrix.items() %}
    <tr><td><code>{{ ctrl }}</code></td><td>{{ n }}</td></tr>
    {% endfor %}
  </table>
</div>
</body>
</html>""")


def render_html(findings, account="(demo)"):
    """Render the full HTML report string."""
    ordered = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f["severity"]),
    )
    return _HTML_TEMPLATE.render(
        account=account,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        summary=_AttrDict(summarise(findings)),
        findings=ordered,
        matrix=framework_matrix(findings),
    )


class _AttrDict(dict):
    """Dict that also supports attribute access, for tidy Jinja templates."""
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc

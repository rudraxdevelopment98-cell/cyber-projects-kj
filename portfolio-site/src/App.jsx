import { useState } from "react";

const projects = [
  {
    id: 1,
    num: "01",
    title: "SOC Home Lab",
    subtitle: "Real-Time Threat Detection with Splunk & Atomic Red Team",
    category: "SOC / SIEM / Blue Team",
    duration: "3–4 weeks",
    difficulty: "Advanced",
    color: "#00d4ff",
    icon: "🛡️",
    repo: "https://github.com/rudraxdevelopment98-cell/cyber-projects-kj/tree/main/01-soc-home-lab",
    tools: ["Splunk", "Sysmon", "Atomic Red Team", "Kali Linux", "Windows Event Logs", "Python"],
    cvHeadline: "Built a fully operational SOC home lab using Splunk SIEM, simulated 15+ MITRE ATT&CK techniques using Atomic Red Team, and documented 10+ detection use cases with triage playbooks",
    bullets: [
      "Designed and deployed a SOC home lab with Splunk SIEM, Sysmon, and Atomic Red Team to simulate and detect 15+ MITRE ATT&CK techniques",
      "Developed 10+ Splunk SPL detection queries covering credential dumping, brute force, and malicious PowerShell execution",
      "Produced professional incident response reports documenting attack timelines, IOCs, and remediation steps",
      "Configured log ingestion pipeline using Splunk Universal Forwarder to centralise Windows Event Logs and Sysmon telemetry"
    ],
    deliverables: ["GitHub repo with setup guide", "10+ Splunk detection use cases (SPL)", "Incident Response Report (PDF)", "MITRE ATT&CK Navigator layer", "Splunk dashboard screenshots"],
    certs: ["Splunk Core Certified User", "TryHackMe SOC Level 1", "CompTIA Security+"],
    mitre: ["T1059 PowerShell", "T1003 Credential Dump", "T1078 Valid Accounts", "T1547 Persistence", "T1071 C2 Protocol"]
  },
  {
    id: 2,
    num: "02",
    title: "AWS Cloud Security Audit",
    subtitle: "Automated Misconfiguration Detection & CIS Benchmark Reporting",
    category: "Cloud Security / AWS / Python",
    duration: "2–3 weeks",
    difficulty: "Advanced",
    color: "#ff6b2b",
    icon: "☁️",
    repo: "https://github.com/rudraxdevelopment98-cell/cyber-projects-kj/tree/main/02-aws-security-audit",
    tools: ["Python", "Boto3", "AWS Free Tier", "AWS CLI", "Prowler", "ReportLab"],
    cvHeadline: "Developed a Python/Boto3 AWS security audit tool identifying 20+ misconfiguration types across IAM, S3, EC2, and CloudTrail — mapped to CIS AWS Benchmark v1.5 and NIST CSF controls",
    bullets: [
      "Developed a Python/Boto3 AWS security audit tool performing 20+ automated checks across IAM, S3, EC2, and CloudTrail",
      "Mapped all findings to CIS AWS Benchmark v1.5 and NIST Cybersecurity Framework, producing executive-grade PDF reports",
      "Identified critical misconfigurations including public S3 buckets, unrestricted SSH, and disabled CloudTrail logging",
      "Demonstrated Cloud Security Posture Management (CSPM) concepts aligned with real-world SOC operations"
    ],
    deliverables: ["Python source code (GitHub)", "Sample PDF security audit report", "JSON findings output", "CIS/NIST framework mapping", "Optional: Streamlit findings dashboard"],
    certs: ["AWS Cloud Practitioner", "CompTIA Security+", "ISC2 CC"],
    checks: ["IAM root MFA disabled", "Public S3 buckets", "SSH open to 0.0.0.0/0", "CloudTrail not enabled", "IAM admin over-provisioning", "S3 logging disabled", "Log validation off"]
  },
  {
    id: 3,
    num: "03",
    title: "Threat Intelligence Dashboard",
    subtitle: "IOC Aggregator, Enrichment Engine & Live Analyst Dashboard",
    category: "Threat Intel / OSINT / Automation",
    duration: "3–4 weeks",
    difficulty: "Advanced",
    color: "#b44dff",
    icon: "🔍",
    repo: "https://github.com/rudraxdevelopment98-cell/cyber-projects-kj/tree/main/03-threat-intel-dashboard",
    tools: ["Python", "Streamlit", "VirusTotal API", "AbuseIPDB", "AlienVault OTX", "SQLite", "Plotly"],
    cvHeadline: "Built a Python threat intelligence platform aggregating IOCs from 5+ OSINT feeds, automated enrichment via VirusTotal & AbuseIPDB APIs, with live Streamlit dashboard — deployed publicly for portfolio",
    bullets: [
      "Aggregated IOCs from 5 open-source feeds (AlienVault OTX, URLhaus, ThreatFox, Feodo Tracker, AbuseIPDB) via automated Python pipeline",
      "Built risk-scoring engine combining VirusTotal detection ratios and AbuseIPDB confidence scores to prioritise high-risk indicators",
      "Deployed interactive Streamlit dashboard with IOC tables, risk charts, and threat trend visualisations — accessible via public URL",
      "Mapped enriched IOC data to MITRE ATT&CK threat actor profiles, supporting threat hunting workflows"
    ],
    deliverables: ["GitHub repo + public Streamlit URL", "Live IOC enrichment dashboard", "Risk scoring engine (Python)", "Daily threat report generator", "Splunk lookup table export"],
    certs: ["CompTIA CySA+", "TryHackMe Threat Intelligence", "Recorded Future (free cert)"],
    feeds: ["AlienVault OTX", "URLhaus (abuse.ch)", "Feodo Tracker", "ThreatFox", "AbuseIPDB"]
  }
];

export default function App() {
  const [active, setActive] = useState(0);
  const [tab, setTab] = useState("bullets");
  const p = projects[active];

  return (
    <div style={{
      fontFamily: "'Courier New', monospace",
      background: "#060a0f",
      minHeight: "100vh",
      color: "#c8d6e5",
      padding: "0"
    }}>
      {/* Header */}
      <div style={{
        borderBottom: "1px solid #1a2a3a",
        padding: "20px 28px",
        display: "flex",
        alignItems: "center",
        gap: "12px",
        background: "linear-gradient(90deg, #060a0f 0%, #0d1824 100%)"
      }}>
        <div style={{
          width: 8, height: 8, borderRadius: "50%",
          background: "#00d4ff",
          boxShadow: "0 0 8px #00d4ff"
        }} />
        <span style={{ color: "#00d4ff", fontSize: 11, letterSpacing: 3, textTransform: "uppercase" }}>
          KULDEEP J. JOTANIYA
        </span>
        <span style={{ color: "#2a4a6a", marginLeft: "auto", fontSize: 11 }}>
          SOC ANALYST PORTFOLIO — 3 ADVANCED PROJECTS
        </span>
      </div>

      <div style={{ display: "flex", minHeight: "calc(100vh - 57px)", flexWrap: "wrap" }}>
        {/* Sidebar */}
        <div style={{
          width: 220,
          borderRight: "1px solid #1a2a3a",
          padding: "24px 0",
          flexShrink: 0
        }}>
          <div style={{ padding: "0 16px 16px", fontSize: 10, color: "#2a4a6a", letterSpacing: 2 }}>
            SELECT PROJECT
          </div>
          {projects.map((proj, i) => (
            <div key={i}
              onClick={() => { setActive(i); setTab("bullets"); }}
              style={{
                padding: "16px 20px",
                cursor: "pointer",
                borderLeft: active === i ? `2px solid ${proj.color}` : "2px solid transparent",
                background: active === i ? "rgba(255,255,255,0.03)" : "transparent",
                transition: "all 0.2s"
              }}>
              <div style={{ fontSize: 20, marginBottom: 4 }}>{proj.icon}</div>
              <div style={{
                fontSize: 10,
                color: proj.color,
                letterSpacing: 2,
                marginBottom: 4,
                opacity: active === i ? 1 : 0.4
              }}>
                PROJECT {proj.num}
              </div>
              <div style={{
                fontSize: 12,
                color: active === i ? "#e8f4ff" : "#3a5a7a",
                lineHeight: 1.4,
                fontFamily: "sans-serif"
              }}>
                {proj.title}
              </div>
              <div style={{
                marginTop: 6,
                fontSize: 9,
                color: active === i ? proj.color : "#2a4a6a",
                letterSpacing: 1
              }}>
                {proj.duration}
              </div>
            </div>
          ))}

          <div style={{ margin: "24px 16px 0", padding: "12px", background: "#0a1520", borderRadius: 4, border: "1px solid #1a2a3a" }}>
            <div style={{ fontSize: 9, color: "#2a4a6a", letterSpacing: 2, marginBottom: 8 }}>STACK OVERVIEW</div>
            {["Splunk", "Python", "AWS", "Streamlit", "VirusTotal API", "Atomic Red Team"].map(t => (
              <div key={t} style={{ fontSize: 10, color: "#4a7a9a", marginBottom: 4, fontFamily: "sans-serif" }}>▸ {t}</div>
            ))}
          </div>
        </div>

        {/* Main */}
        <div style={{ flex: 1, minWidth: 320, padding: "28px 32px", overflowY: "auto" }}>
          {/* Title block */}
          <div style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
              <span style={{ fontSize: 32 }}>{p.icon}</span>
              <div>
                <div style={{ fontSize: 10, color: p.color, letterSpacing: 3, marginBottom: 4 }}>
                  {p.category}
                </div>
                <h1 style={{ margin: 0, fontSize: 22, color: "#e8f4ff", fontFamily: "sans-serif", fontWeight: 700 }}>
                  {p.title}
                </h1>
              </div>
              <div style={{
                marginLeft: "auto",
                padding: "4px 12px",
                background: `${p.color}18`,
                border: `1px solid ${p.color}40`,
                borderRadius: 2,
                fontSize: 10,
                color: p.color,
                letterSpacing: 2
              }}>
                {p.difficulty.toUpperCase()}
              </div>
            </div>
            <p style={{ margin: 0, color: "#5a8aaa", fontSize: 13, fontFamily: "sans-serif", lineHeight: 1.5 }}>
              {p.subtitle}
            </p>
          </div>

          {/* CV Headline Box */}
          <div style={{
            background: `${p.color}08`,
            border: `1px solid ${p.color}30`,
            borderLeft: `3px solid ${p.color}`,
            padding: "14px 18px",
            marginBottom: 24,
            borderRadius: "0 4px 4px 0"
          }}>
            <div style={{ fontSize: 9, color: p.color, letterSpacing: 2, marginBottom: 6 }}>CV HEADLINE</div>
            <p style={{ margin: 0, fontSize: 12, color: "#b8d4e8", fontFamily: "sans-serif", lineHeight: 1.6 }}>
              {p.cvHeadline}
            </p>
          </div>

          {/* View on GitHub */}
          <a href={p.repo} target="_blank" rel="noreferrer" style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            padding: "8px 14px", marginBottom: 24,
            background: `${p.color}12`, border: `1px solid ${p.color}40`,
            borderRadius: 4, color: p.color, textDecoration: "none",
            fontSize: 11, letterSpacing: 1, fontFamily: "sans-serif"
          }}>
            ▸ View source on GitHub
          </a>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 0, marginBottom: 20, borderBottom: "1px solid #1a2a3a", flexWrap: "wrap" }}>
            {["bullets", "tools", "deliverables", "certs"].map(t => (
              <button key={t}
                onClick={() => setTab(t)}
                style={{
                  background: "none",
                  border: "none",
                  borderBottom: tab === t ? `2px solid ${p.color}` : "2px solid transparent",
                  color: tab === t ? p.color : "#3a5a7a",
                  padding: "8px 16px",
                  fontSize: 10,
                  letterSpacing: 2,
                  cursor: "pointer",
                  textTransform: "uppercase",
                  marginBottom: -1,
                  transition: "all 0.2s"
                }}>
                {t === "bullets" ? "CV BULLETS" : t === "tools" ? "TOOLS" : t === "deliverables" ? "DELIVERABLES" : "CERTIFICATIONS"}
              </button>
            ))}
          </div>

          {/* Tab content */}
          {tab === "bullets" && (
            <div>
              <div style={{ fontSize: 10, color: "#2a4a6a", letterSpacing: 2, marginBottom: 14 }}>
                COPY THESE DIRECTLY INTO YOUR CV PROJECTS SECTION
              </div>
              {p.bullets.map((b, i) => (
                <div key={i} style={{
                  display: "flex",
                  gap: 12,
                  marginBottom: 14,
                  padding: "12px 14px",
                  background: "#0a1520",
                  borderRadius: 4,
                  border: "1px solid #1a2a3a"
                }}>
                  <span style={{ color: p.color, flexShrink: 0, marginTop: 1 }}>▸</span>
                  <span style={{ fontSize: 12, color: "#b8d4e8", fontFamily: "sans-serif", lineHeight: 1.6 }}>{b}</span>
                </div>
              ))}

              {/* MITRE / Checks / Feeds preview */}
              {p.mitre && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ fontSize: 10, color: "#2a4a6a", letterSpacing: 2, marginBottom: 10 }}>MITRE ATT&CK TECHNIQUES SIMULATED</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {p.mitre.map(m => (
                      <span key={m} style={{ padding: "4px 10px", background: "#0a1520", border: `1px solid ${p.color}30`, borderRadius: 2, fontSize: 10, color: "#6a9aaa", fontFamily: "sans-serif" }}>{m}</span>
                    ))}
                  </div>
                </div>
              )}
              {p.checks && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ fontSize: 10, color: "#2a4a6a", letterSpacing: 2, marginBottom: 10 }}>AUDIT CHECKS IMPLEMENTED</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {p.checks.map(c => (
                      <span key={c} style={{ padding: "4px 10px", background: "#0a1520", border: `1px solid ${p.color}30`, borderRadius: 2, fontSize: 10, color: "#6a9aaa", fontFamily: "sans-serif" }}>{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {p.feeds && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ fontSize: 10, color: "#2a4a6a", letterSpacing: 2, marginBottom: 10 }}>THREAT FEEDS INTEGRATED</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {p.feeds.map(f => (
                      <span key={f} style={{ padding: "4px 10px", background: "#0a1520", border: `1px solid ${p.color}30`, borderRadius: 2, fontSize: 10, color: "#6a9aaa", fontFamily: "sans-serif" }}>{f}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === "tools" && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 12 }}>
              {p.tools.map((t, i) => (
                <div key={i} style={{
                  padding: "14px 16px",
                  background: "#0a1520",
                  border: `1px solid ${p.color}25`,
                  borderRadius: 4,
                  display: "flex",
                  alignItems: "center",
                  gap: 10
                }}>
                  <div style={{ width: 6, height: 6, background: p.color, borderRadius: "50%", flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: "#b8d4e8", fontFamily: "sans-serif" }}>{t}</span>
                </div>
              ))}
            </div>
          )}

          {tab === "deliverables" && (
            <div>
              {p.deliverables.map((d, i) => (
                <div key={i} style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  padding: "12px 14px",
                  marginBottom: 10,
                  background: "#0a1520",
                  border: "1px solid #1a2a3a",
                  borderRadius: 4
                }}>
                  <div style={{
                    width: 22, height: 22, borderRadius: "50%",
                    background: `${p.color}20`,
                    border: `1px solid ${p.color}50`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 10, color: p.color, flexShrink: 0
                  }}>
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <span style={{ fontSize: 12, color: "#b8d4e8", fontFamily: "sans-serif" }}>{d}</span>
                </div>
              ))}
            </div>
          )}

          {tab === "certs" && (
            <div>
              <div style={{ fontSize: 10, color: "#2a4a6a", letterSpacing: 2, marginBottom: 14 }}>
                BUILD THESE CERTS ALONGSIDE THE PROJECT
              </div>
              {p.certs.map((c, i) => (
                <div key={i} style={{
                  padding: "12px 16px",
                  marginBottom: 10,
                  background: "#0a1520",
                  border: `1px solid ${p.color}25`,
                  borderRadius: 4,
                  display: "flex",
                  alignItems: "center",
                  gap: 10
                }}>
                  <span style={{ color: p.color }}>🏅</span>
                  <span style={{ fontSize: 12, color: "#b8d4e8", fontFamily: "sans-serif" }}>{c}</span>
                </div>
              ))}
            </div>
          )}

          {/* Build order tip */}
          <div style={{
            marginTop: 32,
            padding: "14px 18px",
            background: "#0a1520",
            border: "1px solid #1a2a3a",
            borderRadius: 4
          }}>
            <div style={{ fontSize: 9, color: "#2a4a6a", letterSpacing: 2, marginBottom: 8 }}>RECOMMENDED BUILD ORDER</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {["① AWS Audit (fastest)", "② SOC Home Lab (most impactful)", "③ Threat Intel Dashboard (most impressive)"].map((s, i) => (
                <span key={i} style={{ fontSize: 11, color: "#5a8aaa", fontFamily: "sans-serif" }}>{s}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

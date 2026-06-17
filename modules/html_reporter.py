"""
HTML report generator with interactive D3.js attack graph visualization.
"""

import json
import os
from datetime import datetime


class HTMLReporter:
    def __init__(self, results):
        self.results = results

    def generate(self, output_path: str) -> str:
        graph_json = json.dumps(self.results.graph_data)
        attack_paths_json = json.dumps([
            {
                "source": p.source,
                "target": p.target,
                "technique": p.technique,
                "description": p.description,
                "severity": p.severity,
                "permissions": p.permissions_used,
                "mitre": p.mitre_id,
                "steps": p.path_steps,
                "blocked": p.blocked_by_scp,
                "blocking_scp": p.blocking_scp,
                "condition_result": p.condition_result,
                "condition_explanation": p.condition_explanation
            }
            for p in self.results.attack_paths
        ])

        sensitive_json = json.dumps({
            "secrets": self.results.sensitive_resources["secrets"][:20],
            "s3_buckets": [b for b in self.results.sensitive_resources["s3_buckets"] if b["flags"]][:20],
            "ssm_params": self.results.sensitive_resources["ssm_params"][:20]
        })

        scp_json = json.dumps(self.results.summary.get("scp_summary", {}))
        summary = self.results.summary
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Attack Path Report — {self.results.account_id}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
  :root {{
    --bg: #0a0e1a;
    --surface: #111827;
    --surface2: #1a2235;
    --border: #1e2d45;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --red: #ef4444;
    --orange: #f97316;
    --yellow: #eab308;
    --blue: #3b82f6;
    --purple: #8b5cf6;
    --green: #22c55e;
    --font-mono: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b2e 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 24px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
  }}
  .header-left {{ display: flex; align-items: center; gap: 16px; }}
  .logo {{
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--red), #7f1d1d);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }}
  .header h1 {{ font-size: 18px; font-weight: 700; }}
  .header .sub {{ font-size: 12px; color: var(--text-dim); font-family: var(--font-mono); }}
  .header-meta {{ text-align: right; font-size: 12px; color: var(--text-dim); font-family: var(--font-mono); }}
  .header-meta strong {{ color: var(--text); }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 40px;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }}
  .card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--accent, var(--blue));
  }}
  .card.danger {{ --accent: var(--red); }}
  .card.warn {{ --accent: var(--orange); }}
  .card.info {{ --accent: var(--blue); }}
  .card.purple {{ --accent: var(--purple); }}
  .card.success {{ --accent: var(--green); }}
  .card-value {{ font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
  .card-label {{ font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; }}
  .card-sub {{ font-size: 11px; color: var(--text-dim); margin-top: 8px; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; text-transform: uppercase;
  }}
  .badge.critical {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
  .badge.high {{ background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
  .badge.medium {{ background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }}
  .badge.low {{ background: rgba(59,130,246,0.2); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); }}
  .badge.blocked {{ background: rgba(34,197,94,0.2); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }}
  .section {{ margin-bottom: 48px; }}
  .section-header {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 20px; padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }}
  .section-title {{
    font-size: 16px; font-weight: 700;
    display: flex; align-items: center; gap: 10px;
  }}
  .section-title .icon {{
    width: 28px; height: 28px; border-radius: 6px;
    background: rgba(239,68,68,0.15);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px;
  }}
  .graph-container {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }}
  .graph-toolbar {{
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    display: flex; gap: 8px; align-items: center;
  }}
  .graph-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px; border-radius: 6px;
    font-size: 12px; cursor: pointer;
    transition: all 0.15s;
  }}
  .graph-btn:hover {{ border-color: var(--blue); color: var(--blue); }}
  .graph-legend {{ margin-left: auto; display: flex; gap: 16px; }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-dim); }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  #attack-graph {{ width: 100%; height: 520px; }}
  .paths-table {{ width: 100%; border-collapse: collapse; }}
  .paths-table th {{
    text-align: left; padding: 10px 16px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-dim);
  }}
  .paths-table td {{
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  .paths-table tr:hover td {{ background: var(--surface2); }}
  .paths-table tr.blocked-row td {{ opacity: 0.5; }}
  .paths-table tr:last-child td {{ border-bottom: none; }}
  .identity-cell {{ font-family: var(--font-mono); font-size: 12px; color: var(--blue); max-width: 200px; word-break: break-all; }}
  .technique-cell {{ font-weight: 600; color: var(--yellow); }}
  .perms-cell {{ font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }}
  .mitre-link {{ font-family: var(--font-mono); font-size: 11px; color: var(--purple); text-decoration: none; }}
  .mitre-link:hover {{ color: var(--blue); }}
  .detail-panel {{
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; margin-top: 8px;
    display: none; font-size: 12px;
  }}
  .step-list {{ list-style: none; }}
  .step-list li {{
    padding: 6px 0; border-bottom: 1px solid var(--border);
    display: flex; gap: 8px; align-items: flex-start;
  }}
  .step-list li:last-child {{ border-bottom: none; }}
  .step-num {{
    min-width: 20px; height: 20px; background: var(--red);
    border-radius: 4px; display: flex; align-items: center; justify-content: center;
    font-size: 10px; font-weight: 700;
  }}
  .scp-table {{ width: 100%; border-collapse: collapse; }}
  .scp-table th {{
    text-align: left; padding: 10px 16px;
    background: rgba(34,197,94,0.1);
    border-bottom: 1px solid rgba(34,197,94,0.2);
    font-size: 11px; text-transform: uppercase;
    color: var(--green);
  }}
  .scp-table td {{ padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 12px; }}
  .scp-table tr:last-child td {{ border-bottom: none; }}
  .resource-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
  .resource-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  .resource-card-header {{
    padding: 12px 16px; background: var(--surface2);
    border-bottom: 1px solid var(--border);
    font-weight: 600; font-size: 13px;
    display: flex; align-items: center; gap: 8px;
  }}
  .resource-item {{ padding: 10px 16px; border-bottom: 1px solid var(--border); font-family: var(--font-mono); font-size: 12px; }}
  .resource-item:last-child {{ border-bottom: none; }}
  .resource-item .meta {{ color: var(--text-dim); font-size: 11px; margin-top: 2px; }}
  .resource-flag {{
    display: inline-block; padding: 1px 6px; border-radius: 3px;
    font-size: 10px; font-weight: 600;
    background: rgba(239,68,68,0.15); color: var(--red);
    border: 1px solid rgba(239,68,68,0.3); margin-left: 6px;
  }}
  .tooltip {{
    position: fixed; background: var(--surface2);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 14px; font-size: 12px;
    pointer-events: none; z-index: 999; max-width: 280px;
    display: none; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  }}
  .no-paths {{ text-align: center; padding: 48px; color: var(--text-dim); }}
  .no-paths .icon {{ font-size: 48px; margin-bottom: 16px; }}
  .footer {{
    border-top: 1px solid var(--border); padding: 24px 40px; margin-top: 40px;
    display: flex; justify-content: space-between; align-items: center;
    color: var(--text-dim); font-size: 12px; font-family: var(--font-mono);
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-left">
    <div class="logo">⚔️</div>
    <div>
      <h1>AWS Attack Path Analyzer</h1>
      <div class="sub">Privilege Escalation & Lateral Movement Report</div>
    </div>
  </div>
  <div class="header-meta">
    <div><strong>Account:</strong> {self.results.account_id}</div>
    <div><strong>Region:</strong> {self.results.region}</div>
    <div><strong>Generated:</strong> {timestamp}</div>
  </div>
</header>

<div class="container">

  <div class="summary-grid">
    <div class="card info">
      <div class="card-value" style="color:var(--blue)">{summary['total_identities']}</div>
      <div class="card-label">Identities Scanned</div>
    </div>
    <div class="card danger">
      <div class="card-value" style="color:var(--red)">{summary['exploitable_paths']}</div>
      <div class="card-label">Exploitable Paths</div>
      <div class="card-sub">Not blocked by SCPs</div>
    </div>
    <div class="card success">
      <div class="card-value" style="color:var(--green)">{summary['blocked_by_scp']}</div>
      <div class="card-label">Blocked by SCP</div>
      <div class="card-sub">SCPs preventing exploitation</div>
    </div>
    <div class="card danger">
      <div class="card-value" style="color:var(--red)">{summary['severity_counts'].get('critical', 0)}</div>
      <div class="card-label">Critical Paths</div>
    </div>
    <div class="card warn">
      <div class="card-value" style="color:var(--orange)">{summary['severity_counts'].get('high', 0)}</div>
      <div class="card-label">High Severity</div>
    </div>
    <div class="card info">
      <div class="card-value" style="color:var(--yellow)">{summary['sensitive_resources']['secrets']}</div>
      <div class="card-label">Secrets Found</div>
    </div>
  </div>

  <!-- ATTACK GRAPH -->
  <div class="section">
    <div class="section-header">
      <div class="section-title"><div class="icon">🕸️</div>Attack Path Graph</div>
      <div style="font-size:12px;color:var(--text-dim)">Grey nodes = blocked by SCP</div>
    </div>
    <div class="graph-container">
      <div class="graph-toolbar">
        <button class="graph-btn" onclick="resetZoom()">⟳ Reset</button>
        <button class="graph-btn" onclick="zoomIn()">＋ Zoom In</button>
        <button class="graph-btn" onclick="zoomOut()">－ Zoom Out</button>
        <div class="graph-legend">
          <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div>User</div>
          <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6"></div>Role</div>
          <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div>Technique</div>
          <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div>Target</div>
          <div class="legend-item"><div class="legend-dot" style="background:#374151"></div>Blocked</div>
        </div>
      </div>
      <svg id="attack-graph"></svg>
    </div>
  </div>

  <!-- SCP COVERAGE -->
  <div class="section">
    <div class="section-header">
      <div class="section-title"><div class="icon" style="background:rgba(34,197,94,0.15)">🛡️</div>SCP Coverage</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table class="scp-table" id="scp-table">
        <thead>
          <tr>
            <th>SCP Name</th>
            <th>Policy ID</th>
            <th>Target</th>
            <th>Denied Actions</th>
          </tr>
        </thead>
        <tbody id="scp-tbody"></tbody>
      </table>
      <div class="no-paths" id="no-scps" style="display:none">
        <div class="icon">⚠️</div>
        <div>No restrictive SCPs detected. All paths may be exploitable.</div>
      </div>
    </div>
  </div>

  <!-- ATTACK PATHS -->
  <div class="section">
    <div class="section-header">
      <div class="section-title"><div class="icon">🎯</div>Attack Paths</div>
      <div style="display:flex;gap:8px;">
        <button class="graph-btn" onclick="filterPaths('all')">All</button>
        <button class="graph-btn" onclick="filterPaths('exposed')" style="color:var(--red)">Exposed Only</button>
        <button class="graph-btn" onclick="filterPaths('blocked')" style="color:var(--green)">Blocked Only</button>
        <button class="graph-btn" onclick="filterPaths('critical')" style="color:var(--red)">Critical</button>
      </div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table class="paths-table" id="paths-table">
        <thead>
          <tr>
            <th>Sev</th>
            <th>Status</th>
            <th>Source Identity</th>
            <th>Technique</th>
            <th>Description</th>
            <th>Permissions</th>
            <th>MITRE</th>
          </tr>
        </thead>
        <tbody id="paths-tbody"></tbody>
      </table>
      <div class="no-paths" id="no-paths" style="display:none">
        <div class="icon">✅</div>
        <div>No paths match this filter.</div>
      </div>
    </div>
  </div>

  <!-- SENSITIVE RESOURCES -->
  <div class="section">
    <div class="section-header">
      <div class="section-title"><div class="icon">🔐</div>Sensitive Resources</div>
    </div>
    <div class="resource-grid" id="resource-grid"></div>
  </div>

</div>

<footer class="footer">
  <div>AWS Attack Path Analyzer — GeekyBlessing Portfolio</div>
  <div>Account: {self.results.account_id} | {timestamp}</div>
</footer>

<div class="tooltip" id="tooltip">
  <div id="tt-title" style="font-weight:700;margin-bottom:4px;"></div>
  <div id="tt-type" style="color:var(--text-dim);font-size:11px;"></div>
</div>

<script>
const GRAPH_DATA = {graph_json};
const ATTACK_PATHS = {attack_paths_json};
const SENSITIVE = {sensitive_json};
const SCP_DATA = {scp_json};

// ── D3 Graph ────────────────────────────────────────────────────────────────
(function() {{
  const svg = d3.select("#attack-graph");
  const width = svg.node().parentElement.clientWidth;
  const height = 520;
  svg.attr("viewBox", [0, 0, width, height]);
  const g = svg.append("g");

  const zoom = d3.zoom().scaleExtent([0.3, 4]).on("zoom", e => g.attr("transform", e.transform));
  svg.call(zoom);
  window.resetZoom = () => svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
  window.zoomIn = () => svg.transition().duration(300).call(zoom.scaleBy, 1.4);
  window.zoomOut = () => svg.transition().duration(300).call(zoom.scaleBy, 0.7);

  if (!GRAPH_DATA.nodes.length) {{
    svg.append("text").attr("x", width/2).attr("y", height/2)
      .attr("text-anchor", "middle").attr("fill", "#64748b")
      .text("No attack paths to visualize");
    return;
  }}

  const defs = svg.append("defs");
  defs.append("marker").attr("id","arrow").attr("viewBox","0 -5 10 10")
    .attr("refX",20).attr("refY",0).attr("markerWidth",6).attr("markerHeight",6)
    .attr("orient","auto").append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#4b5563");

  const simulation = d3.forceSimulation(GRAPH_DATA.nodes)
    .force("link", d3.forceLink(GRAPH_DATA.edges).id(d=>d.id).distance(140).strength(0.6))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(width/2, height/2))
    .force("collision", d3.forceCollide().radius(45));

  const link = g.append("g").selectAll("line").data(GRAPH_DATA.edges).join("line")
    .attr("stroke","#374151").attr("stroke-width",2).attr("marker-end","url(#arrow)");

  const edgeLabel = g.append("g").selectAll("text").data(GRAPH_DATA.edges).join("text")
    .attr("font-size",9).attr("fill","#6b7280").attr("text-anchor","middle")
    .text(d => d.label ? (d.label.length>30 ? d.label.slice(0,30)+"…" : d.label) : "");

  const nodeGroup = g.append("g").selectAll("g").data(GRAPH_DATA.nodes).join("g")
    .attr("cursor","grab")
    .call(d3.drag()
      .on("start",(e,d)=>{{ if(!e.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x;d.fy=d.y; }})
      .on("drag",(e,d)=>{{ d.fx=e.x;d.fy=e.y; }})
      .on("end",(e,d)=>{{ if(!e.active) simulation.alphaTarget(0); d.fx=null;d.fy=null; }}))
    .on("mouseover",(e,d)=>{{
      const tt=document.getElementById("tooltip");
      document.getElementById("tt-title").textContent=d.label||d.arn;
      document.getElementById("tt-type").textContent=`Type: ${{d.type}}${{d.blocked?" | BLOCKED BY SCP":""}}`;
      tt.style.display="block";
      tt.style.left=(e.clientX+12)+"px"; tt.style.top=(e.clientY-8)+"px";
    }})
    .on("mousemove",e=>{{
      document.getElementById("tooltip").style.left=(e.clientX+12)+"px";
      document.getElementById("tooltip").style.top=(e.clientY-8)+"px";
    }})
    .on("mouseout",()=>{{ document.getElementById("tooltip").style.display="none"; }});

  const r = d => d.type==="target"?20:d.type==="technique"?16:18;

  nodeGroup.append("circle").attr("r",r)
    .attr("fill",d=>d.color)
    .attr("stroke",d=>d.blocked?"#22c55e":d.type==="target"?"#ff0000":"#1e2d45")
    .attr("stroke-width",d=>d.blocked?2:d.type==="target"?3:1.5)
    .attr("stroke-dasharray",d=>d.blocked?"4,2":"none")
    .attr("opacity",0.9);

  nodeGroup.append("text").attr("text-anchor","middle").attr("dy",".35em")
    .attr("font-size",10).attr("font-weight","bold").attr("fill","white")
    .text(d=>{{ const l=d.label||""; return l.length>12?l.slice(0,11)+"…":l; }});

  nodeGroup.append("text").attr("text-anchor","middle")
    .attr("y",d=>r(d)+14).attr("font-size",9).attr("fill","#94a3b8")
    .text(d=>d.blocked?"BLOCKED":d.type.toUpperCase());

  simulation.on("tick",()=>{{
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
        .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    edgeLabel.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2);
    nodeGroup.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
  }});
}})();

// ── SCP Table ────────────────────────────────────────────────────────────────
(function() {{
  const tbody = document.getElementById("scp-tbody");
  const noScps = document.getElementById("no-scps");
  const scps = (SCP_DATA.scps||[]).filter(s=>s.type==="Restrictive");

  if (!scps.length) {{
    document.getElementById("scp-table").style.display="none";
    noScps.style.display="block";
    return;
  }}

  scps.forEach(scp=>{{
    const denied = scp.denied_actions||[];
    const preview = denied.slice(0,5).join(", ") + (denied.length>5?` +${{denied.length-5}} more`:"");
    const tr = document.createElement("tr");
    tr.innerHTML=`
      <td style="color:var(--green);font-weight:600">${{scp.name}}</td>
      <td style="font-family:monospace;color:var(--text-dim)">${{scp.id}}</td>
      <td style="font-family:monospace;color:var(--blue)">${{scp.target}}</td>
      <td style="font-family:monospace;font-size:11px;color:var(--red)">${{preview||"<span style='color:var(--text-dim)'>none parsed</span>"}}</td>
    `;
    tbody.appendChild(tr);
  }});
}})();

// ── Paths Table ──────────────────────────────────────────────────────────────
function renderPaths(filter) {{
  const tbody = document.getElementById("paths-tbody");
  const noPathsEl = document.getElementById("no-paths");
  const tableEl = document.getElementById("paths-table");
  tbody.innerHTML="";

  const sev_order = {{critical:4,high:3,medium:2,low:1}};
  const sorted = [...ATTACK_PATHS].sort((a,b)=>
    (b.blocked?0:sev_order[b.severity]||0) - (a.blocked?0:sev_order[a.severity]||0));

  let filtered = sorted;
  if (filter==="exposed") filtered=sorted.filter(p=>!p.blocked);
  else if (filter==="blocked") filtered=sorted.filter(p=>p.blocked);
  else if (filter==="critical") filtered=sorted.filter(p=>p.severity==="critical"&&!p.blocked);

  if (!filtered.length) {{
    tableEl.style.display="none"; noPathsEl.style.display="block"; return;
  }}
  tableEl.style.display=""; noPathsEl.style.display="none";

  filtered.forEach((path,idx)=>{{
    const sourceName = path.source.split("/").pop();
    const statusBadge = path.blocked
      ? `<span class="badge blocked">🛡 BLOCKED</span><div style="font-size:10px;color:var(--green);margin-top:4px">${{path.blocking_scp}}</div>`
      : path.condition_result === 'CONDITIONAL'
      ? `<span class="badge medium">⚠ CONDITIONAL</span><div style="font-size:10px;color:var(--yellow);margin-top:4px">${{path.condition_explanation}}</div>`
      : `<span class="badge ${{path.severity}}">EXPOSED</span>`;
    const tr = document.createElement("tr");
    if (path.blocked) tr.className="blocked-row";
    tr.innerHTML=`
      <td><span class="badge ${{path.severity}}">${{path.severity.toUpperCase()}}</span></td>
      <td>${{statusBadge}}</td>
      <td><div class="identity-cell" title="${{path.source}}">${{sourceName}}</div></td>
      <td><div class="technique-cell">${{path.technique}}</div></td>
      <td>
        <div>${{path.description}}</div>
        <button onclick="toggleDetail(${{idx}})"
          style="margin-top:6px;background:none;border:1px solid #1e2d45;color:#64748b;padding:3px 8px;border-radius:4px;font-size:11px;cursor:pointer;">
          ▶ View Steps
        </button>
        <div class="detail-panel" id="detail-${{idx}}">
          <ul class="step-list">
            ${{(path.steps||[]).map((s,i)=>`<li><span class="step-num">${{i+1}}</span><span>${{s}}</span></li>`).join("")}}
          </ul>
        </div>
      </td>
      <td><div class="perms-cell">${{(path.permissions||[]).join("<br>")}}</div></td>
      <td><a class="mitre-link" href="https://attack.mitre.org/techniques/${{path.mitre}}/" target="_blank">${{path.mitre}}</a></td>
    `;
    tbody.appendChild(tr);
  }});
}}

function toggleDetail(idx) {{
  const p=document.getElementById(`detail-${{idx}}`);
  p.style.display=p.style.display==="block"?"none":"block";
}}

function filterPaths(f) {{
  renderPaths(f);
  document.querySelectorAll(".graph-btn").forEach(b=>b.style.borderColor="");
  event.target.style.borderColor="#3b82f6";
}}

renderPaths("all");

// ── Resources ────────────────────────────────────────────────────────────────
(function() {{
  const grid=document.getElementById("resource-grid");
  function makeCard(title,icon,items,renderItem) {{
    if(!items.length) return;
    const card=document.createElement("div");
    card.className="resource-card";
    card.innerHTML=`<div class="resource-card-header">${{icon}} ${{title}} <span style="margin-left:auto;color:#64748b;font-size:12px">${{items.length}}</span></div>`;
    items.slice(0,15).forEach(item=>{{
      const el=document.createElement("div");
      el.className="resource-item";
      el.innerHTML=renderItem(item);
      card.appendChild(el);
    }});
    grid.appendChild(card);
  }}
  makeCard("Secrets Manager","🔑",SENSITIVE.secrets,s=>`<div>${{s.name}}</div><div class="meta">${{s.description||s.arn}}</div>`);
  makeCard("SSM Parameters","📋",SENSITIVE.ssm_params,p=>`<div>${{p.name}}</div><div class="meta">Type: ${{p.type}}</div>`);
  makeCard("Flagged S3 Buckets","🪣",SENSITIVE.s3_buckets,b=>`<div>${{b.name}}${{b.flags.map(f=>`<span class="resource-flag">${{f}}</span>`).join("")}}</div>`);
  if(!SENSITIVE.secrets.length&&!SENSITIVE.ssm_params.length&&!SENSITIVE.s3_buckets.length) {{
    grid.innerHTML='<div class="no-paths"><div class="icon">✅</div><div>No sensitive resources with issues detected.</div></div>';
  }}
}})();
</script>
</body>
</html>"""

        if os.path.dirname(output_path):
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return os.path.abspath(output_path)
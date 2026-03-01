"""Report generation for OTScan results."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from otscan.protocols.base import Severity


def scan_result_to_dict(result) -> dict[str, Any]:
    """Convert an OTScanResult to a serializable dictionary."""
    hosts = []
    for host in result.hosts:
        host_dict = {
            "ip": host.ip,
            "hostname": host.hostname,
            "open_ports": host.open_ports,
            "devices": [],
            "vulnerabilities": [],
        }
        for sr in host.scan_results:
            if sr.device:
                host_dict["devices"].append({
                    "protocol": sr.device.protocol,
                    "vendor": sr.device.vendor,
                    "model": sr.device.model,
                    "firmware": sr.device.firmware,
                    "serial": sr.device.serial,
                    "device_type": sr.device.device_type,
                    "description": sr.device.description,
                })
            for vuln in sr.vulnerabilities:
                host_dict["vulnerabilities"].append({
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "protocol": vuln.protocol,
                    "port": vuln.port,
                    "description": vuln.description,
                    "remediation": vuln.remediation,
                    "cve": vuln.cve,
                })
        hosts.append(host_dict)

    return {
        "scan_info": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": result.scan_mode,
            "duration_seconds": round(result.summary.scan_duration, 2),
        },
        "summary": {
            "targets_scanned": result.summary.targets_scanned,
            "hosts_alive": result.summary.hosts_alive,
            "devices_identified": result.summary.devices_identified,
            "total_vulnerabilities": result.summary.total_vulnerabilities,
            "severity_counts": {
                "critical": result.summary.critical_count,
                "high": result.summary.high_count,
                "medium": result.summary.medium_count,
                "low": result.summary.low_count,
                "info": result.summary.info_count,
            },
            "protocols_found": result.summary.protocols_found,
        },
        "hosts": hosts,
    }


def generate_json_report(result, output_path: str) -> str:
    """Generate a JSON report file."""
    data = scan_result_to_dict(result)
    path = Path(output_path)
    path.write_text(json.dumps(data, indent=2))
    return str(path.absolute())


def generate_csv_report(result, output_path: str) -> str:
    """Generate a CSV report of vulnerabilities."""
    path = Path(output_path)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Host", "Port", "Protocol", "Severity", "Title",
        "Description", "Remediation", "CVE",
    ])

    for host in result.hosts:
        for sr in host.scan_results:
            for vuln in sr.vulnerabilities:
                writer.writerow([
                    host.ip,
                    vuln.port,
                    vuln.protocol,
                    vuln.severity.value,
                    vuln.title,
                    vuln.description,
                    vuln.remediation,
                    vuln.cve,
                ])

    path.write_text(output.getvalue())
    return str(path.absolute())


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OTScan Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; padding: 2rem; }
  .header { text-align: center; margin-bottom: 2rem; }
  .header h1 { font-size: 2rem; color: #38bdf8; }
  .header .meta { color: #94a3b8; margin-top: 0.5rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
              gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; padding: 1.5rem; border-radius: 0.5rem;
          text-align: center; }
  .stat .value { font-size: 2rem; font-weight: bold; }
  .stat .label { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .severity-bar { display: flex; gap: 0.5rem; justify-content: center;
                  margin-bottom: 2rem; }
  .severity-badge { padding: 0.5rem 1rem; border-radius: 0.25rem;
                    font-weight: bold; font-size: 0.875rem; }
  .host-card { background: #1e293b; border-radius: 0.5rem;
               margin-bottom: 1.5rem; overflow: hidden; }
  .host-header { padding: 1rem 1.5rem; background: #334155;
                 font-size: 1.125rem; font-weight: bold; }
  .host-body { padding: 1.5rem; }
  .device-info { margin-bottom: 1rem; }
  .device-info table { width: 100%; border-collapse: collapse; }
  .device-info td { padding: 0.375rem 0.75rem; border-bottom: 1px solid #334155; }
  .device-info td:first-child { color: #94a3b8; width: 140px; }
  .vuln { margin-bottom: 1rem; padding: 1rem; border-radius: 0.375rem;
          border-left: 4px solid; background: #0f172a; }
  .vuln h4 { margin-bottom: 0.5rem; }
  .vuln p { font-size: 0.875rem; color: #cbd5e1; margin-bottom: 0.25rem; }
  .vuln .remediation { color: #22d3ee; font-style: italic; }
  .protocols { margin-bottom: 1rem; }
  .protocol-tag { display: inline-block; background: #334155; padding: 0.25rem 0.75rem;
                  border-radius: 1rem; margin: 0.25rem; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="header">
  <h1>OTScan Report</h1>
  <div class="meta">Scan Mode: {mode} | Duration: {duration}s | {timestamp}</div>
</div>

<div class="summary">
  <div class="stat"><div class="value">{targets}</div><div class="label">Targets Scanned</div></div>
  <div class="stat"><div class="value">{alive}</div><div class="label">Hosts Alive</div></div>
  <div class="stat"><div class="value">{devices}</div><div class="label">Devices Identified</div></div>
  <div class="stat"><div class="value">{vulns}</div><div class="label">Vulnerabilities</div></div>
</div>

<div class="severity-bar">
  <span class="severity-badge" style="background:{c_critical}">CRITICAL: {n_critical}</span>
  <span class="severity-badge" style="background:{c_high}">HIGH: {n_high}</span>
  <span class="severity-badge" style="background:{c_medium}">MEDIUM: {n_medium}</span>
  <span class="severity-badge" style="background:{c_low}">LOW: {n_low}</span>
  <span class="severity-badge" style="background:{c_info}">INFO: {n_info}</span>
</div>

{protocols_section}

{hosts_section}

</body>
</html>
"""


def _render_host_card(host, scan_results) -> str:
    """Render a single host card in HTML."""
    hostname_str = f" ({host.hostname})" if host.hostname else ""
    ports_str = ", ".join(str(p) for p in host.open_ports)

    devices_html = ""
    vulns_html = ""

    for sr in scan_results:
        if sr.device:
            d = sr.device
            devices_html += f"""
            <div class="device-info">
              <table>
                <tr><td>Protocol</td><td>{d.protocol}</td></tr>
                <tr><td>Vendor</td><td>{d.vendor}</td></tr>
                <tr><td>Model</td><td>{d.model}</td></tr>
                <tr><td>Firmware</td><td>{d.firmware}</td></tr>
                <tr><td>Type</td><td>{d.device_type}</td></tr>
              </table>
            </div>"""

        for vuln in sr.vulnerabilities:
            color = SEVERITY_COLORS.get(vuln.severity.value, "#6b7280")
            vulns_html += f"""
            <div class="vuln" style="border-color:{color}">
              <h4>[{vuln.severity.value.upper()}] {vuln.title}</h4>
              <p>{vuln.description}</p>
              {f'<p class="remediation">Remediation: {vuln.remediation}</p>' if vuln.remediation else ''}
              {f'<p>CVE: {vuln.cve}</p>' if vuln.cve else ''}
            </div>"""

    return f"""
    <div class="host-card">
      <div class="host-header">{host.ip}{hostname_str} — Open ports: {ports_str}</div>
      <div class="host-body">
        {devices_html}
        {vulns_html if vulns_html else '<p style="color:#94a3b8">No vulnerabilities detected.</p>'}
      </div>
    </div>"""


def generate_html_report(result, output_path: str) -> str:
    """Generate an HTML report."""
    s = result.summary

    protocols_section = ""
    if s.protocols_found:
        tags = "".join(f'<span class="protocol-tag">{p}</span>' for p in s.protocols_found)
        protocols_section = f'<div class="protocols"><strong>Protocols Detected:</strong> {tags}</div>'

    hosts_section = ""
    for host in result.hosts:
        hosts_section += _render_host_card(host, host.scan_results)

    html = HTML_TEMPLATE.format(
        mode=result.scan_mode,
        duration=round(s.scan_duration, 2),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        targets=s.targets_scanned,
        alive=s.hosts_alive,
        devices=s.devices_identified,
        vulns=s.total_vulnerabilities,
        n_critical=s.critical_count,
        n_high=s.high_count,
        n_medium=s.medium_count,
        n_low=s.low_count,
        n_info=s.info_count,
        c_critical=SEVERITY_COLORS["critical"],
        c_high=SEVERITY_COLORS["high"],
        c_medium=SEVERITY_COLORS["medium"],
        c_low=SEVERITY_COLORS["low"],
        c_info=SEVERITY_COLORS["info"],
        protocols_section=protocols_section,
        hosts_section=hosts_section,
    )

    path = Path(output_path)
    path.write_text(html)
    return str(path.absolute())

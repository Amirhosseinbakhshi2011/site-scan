"""Generate security reports in JSON, HTML and PDF."""

import json
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.models.scan import Finding, RiskLevel, Scan


def findings_to_dict(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "id": f.id,
            "check_name": f.check_name,
            "title": f.title,
            "description": f.description,
            "risk_level": f.risk_level.value if hasattr(f.risk_level, "value") else f.risk_level,
            "confidence": f.confidence.value if hasattr(f.confidence, "value") else f.confidence,
            "evidence": f.evidence,
            "affected_url": f.affected_url,
            "http_status": f.http_status,
            "remediation": f.remediation,
            "cwe_id": f.cwe_id,
        }
        for f in findings
    ]


def build_json_report(scan: Scan, hostname: str) -> dict[str, Any]:
    return {
        "report_meta": {
            "generator": "Aegis Sentinel AI",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "language": "fa",
            "scan_id": scan.id,
            "hostname": hostname,
        },
        "summary": {
            "overall_score": scan.overall_score,
            "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "text": scan.summary,
        },
        "findings": findings_to_dict(list(scan.findings) if scan.findings else []),
    }


def write_json_report(scan: Scan, hostname: str, path: Path) -> Path:
    data = build_json_report(scan, hostname)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def build_pdf_report(scan: Scan, hostname: str) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm)
    styles = getSampleStyleSheet()
    # Note: full Persian shaping needs arabic-reshaper + bidi; for simplicity use English titles + data
    story = []
    story.append(Paragraph("Aegis Sentinel AI - Security Assessment Report", styles["Title"]))
    story.append(Paragraph(f"Domain: {hostname} | Scan ID: {scan.id}", styles["Normal"]))
    story.append(Paragraph(f"Score: {scan.overall_score}/100", styles["Heading2"]))
    story.append(Spacer(1, 0.5 * cm))
    if scan.summary:
        story.append(Paragraph(scan.summary, styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    data = [["Risk", "Title", "Check"]]
    for f in (scan.findings or [])[:40]:
        risk = f.risk_level.value if hasattr(f.risk_level, "value") else str(f.risk_level)
        data.append([risk, (f.title or "")[:60], f.check_name])
    if len(data) > 1:
        table = Table(data, colWidths=[2.5 * cm, 9 * cm, 4 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2137")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
    doc.build(story)
    return buffer.getvalue()

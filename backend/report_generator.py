"""
PDF Report Generator
Produces a professional pentest report PDF using ReportLab.
"""

import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ─── Color palette ────────────────────────────────────────────────────────────
BG        = colors.HexColor("#0a0a0a")
SURFACE   = colors.HexColor("#111111")
AMBER     = colors.HexColor("#f5a623")
RED       = colors.HexColor("#e05252")
ORANGE    = colors.HexColor("#e07052")
GREEN     = colors.HexColor("#52c97a")
BLUE      = colors.HexColor("#5299e0")
TEXT      = colors.HexColor("#e8e2d9")
MUTED     = colors.HexColor("#5a5650")
WHITE     = colors.white
BLACK     = colors.black

SEVERITY_COLORS = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   AMBER,
    "low":      GREEN,
    "info":     BLUE,
}


def severity_color(sev: str) -> colors.Color:
    return SEVERITY_COLORS.get(sev.lower(), MUTED)


def get_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=36,
            textColor=WHITE,
            leading=40,
            spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="Helvetica",
            fontSize=13,
            textColor=AMBER,
            spaceAfter=6,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontName="Courier",
            fontSize=9,
            textColor=MUTED,
            spaceAfter=4,
        ),
        "section_head": ParagraphStyle(
            "section_head",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=AMBER,
            spaceBefore=18,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9,
            textColor=TEXT,
            leading=15,
            spaceAfter=6,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=8,
            textColor=AMBER,
            backColor=colors.HexColor("#080808"),
            leading=13,
            leftIndent=8,
            rightIndent=8,
        ),
        "finding_name": ParagraphStyle(
            "finding_name",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=WHITE,
            spaceAfter=2,
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Helvetica-Bold",
            fontSize=7,
            textColor=MUTED,
            spaceBefore=6,
            spaceAfter=2,
        ),
    }
    return styles


def generate_pdf(url: str, report: dict) -> str:
    """Generate a PDF pentest report and return its file path."""

    output_path = os.path.join(tempfile.gettempdir(), f"pentest_report_{int(datetime.now().timestamp())}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=25*mm,
        rightMargin=25*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    S = get_styles()
    story = []

    hostname = urlparse(url).hostname or url
    scan_date = datetime.utcnow().strftime("%B %d, %Y — %H:%M UTC")
    findings = report.get("findings", [])
    risk_score = report.get("risk_score", 0)

    # ── Cover Page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 30*mm))

    # Cover box using a table
    cover_data = [[
        Paragraph("SECURITY ASSESSMENT REPORT", S["cover_title"]),
    ]]
    cover_table = Table(cover_data, colWidths=[160*mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#111111")),
        ("LEFTPADDING", (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("TOPPADDING", (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
        ("LINEABOVE", (0,0), (-1,-1), 3, AMBER),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 8*mm))

    meta_rows = [
        ("Target", hostname),
        ("Full URL", url),
        ("Date", scan_date),
        ("Scanner", "ProbeThat v1.0"),
        ("Report Type", "Automated + AI-Assisted Analysis"),
    ]
    meta_data = [[Paragraph(k, S["label"]), Paragraph(v, S["cover_meta"])] for k, v in meta_rows]
    meta_table = Table(meta_data, colWidths=[35*mm, 125*mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#0d0d0d")),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING", (0,0), (0,-1), 3),
        ("BOTTOMPADDING", (0,0), (0,-1), 3),
        ("LINEBELOW", (0,0), (-1,-2), 0.5, colors.HexColor("#1e1e1e")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12*mm))

    # Risk score badge
    score_class = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW"
    score_color = RED if risk_score >= 70 else ORANGE if risk_score >= 40 else AMBER if risk_score >= 20 else GREEN
    score_data = [[
        Paragraph(f"RISK SCORE", ParagraphStyle("rs_label", fontName="Helvetica-Bold", fontSize=7, textColor=MUTED, alignment=TA_CENTER)),
        Paragraph(f"{risk_score}", ParagraphStyle("rs_num", fontName="Helvetica-Bold", fontSize=42, textColor=score_color, alignment=TA_CENTER)),
        Paragraph(f"{score_class}", ParagraphStyle("rs_class", fontName="Helvetica-Bold", fontSize=14, textColor=score_color, alignment=TA_CENTER)),
    ]]
    score_table = Table([[score_data[0][0]], [score_data[0][1]], [score_data[0][2]]], colWidths=[160*mm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#111111")),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LINEABOVE", (0,0), (-1,0), 0.5, colors.HexColor("#2e2e2e")),
        ("LINEBELOW", (0,-1), (-1,-1), 0.5, colors.HexColor("#2e2e2e")),
    ]))
    story.append(score_table)
    story.append(PageBreak())

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", S["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e1e1e")))
    story.append(Spacer(1, 4*mm))

    exec_summary = report.get("executive_summary", "No summary available.")
    for para in exec_summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), S["body"]))

    # ── Findings Summary Table ─────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("FINDINGS SUMMARY", S["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e1e1e")))
    story.append(Spacer(1, 4*mm))

    severity_order = ["critical", "high", "medium", "low", "info"]
    counts = {s: sum(1 for f in findings if f.get("severity", "").lower() == s) for s in severity_order}

    summary_header = [
        Paragraph("SEVERITY", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=AMBER)),
        Paragraph("COUNT", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=AMBER, alignment=TA_CENTER)),
    ]
    summary_rows = [summary_header]
    for sev in severity_order:
        if counts[sev] > 0:
            summary_rows.append([
                Paragraph(sev.upper(), ParagraphStyle("td_sev", fontName="Helvetica-Bold", fontSize=9, textColor=severity_color(sev))),
                Paragraph(str(counts[sev]), ParagraphStyle("td_count", fontName="Helvetica", fontSize=9, textColor=TEXT, alignment=TA_CENTER)),
            ])

    summary_table = Table(summary_rows, colWidths=[100*mm, 60*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a1a")),
        ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#0d0d0d")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0d0d0d"), colors.HexColor("#111111")]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#1e1e1e")),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # ── Detailed Findings ──────────────────────────────────────────────────────
    story.append(Paragraph("DETAILED FINDINGS", S["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e1e1e")))

    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.get("severity", "info").lower()) if f.get("severity", "info").lower() in severity_order else 5)

    for i, finding in enumerate(sorted_findings):
        sev = finding.get("severity", "info").lower()
        sev_color = severity_color(sev)
        story.append(Spacer(1, 5*mm))

        # Finding header row
        header_row = [[
            Paragraph(f"{i+1:02d}. {finding.get('name', 'Unknown')}", S["finding_name"]),
            Paragraph(sev.upper(), ParagraphStyle(
                "sev_pill",
                fontName="Helvetica-Bold",
                fontSize=8,
                textColor=sev_color,
                alignment=TA_RIGHT,
            )),
        ]]
        header_table = Table(header_row, colWidths=[130*mm, 30*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#111111")),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LINEABOVE", (0,0), (-1,0), 2, sev_color),
        ]))
        story.append(header_table)

        body_rows = []

        # Description
        body_rows.append([
            Paragraph("DESCRIPTION", S["label"]),
            Paragraph(finding.get("description", ""), S["body"]),
        ])

        # Evidence
        if finding.get("evidence"):
            body_rows.append([
                Paragraph("EVIDENCE", S["label"]),
                Paragraph(finding.get("evidence", ""), S["mono"]),
            ])

        # Impact
        body_rows.append([
            Paragraph("IMPACT", S["label"]),
            Paragraph(finding.get("impact", ""), S["body"]),
        ])

        # Remediation
        body_rows.append([
            Paragraph("FIX", S["label"]),
            Paragraph(finding.get("remediation", ""), S["body"]),
        ])

        body_table = Table(body_rows, colWidths=[25*mm, 135*mm])
        body_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#0d0d0d")),
            ("LEFTPADDING", (0,0), (0,-1), 10),
            ("RIGHTPADDING", (0,0), (0,-1), 0),
            ("LEFTPADDING", (0,0), (1,-1), 6),
            ("RIGHTPADDING", (0,0), (1,-1), 10),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LINEBELOW", (0,0), (-1,-2), 0.3, colors.HexColor("#1e1e1e")),
        ]))
        story.append(body_table)

    # ── Footer / Disclaimer ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("DISCLAIMER", S["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e1e1e")))
    story.append(Spacer(1, 4*mm))

    disclaimer = (
        "This report was generated by ProbeThat, an automated security scanning tool. "
        "Automated scanning cannot replace manual penetration testing and may produce false positives or miss vulnerabilities. "
        "This report should be reviewed by a qualified security professional before being used as the sole basis for security decisions. "
        "The scan was conducted only on assets for which the requesting party confirmed ownership or authorization. "
        "ProbeThat and its operators accept no liability for actions taken based on this report."
    )
    story.append(Paragraph(disclaimer, S["body"]))

    # Build PDF with dark page background
    def dark_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Footer line
        canvas.setStrokeColor(colors.HexColor("#1e1e1e"))
        canvas.setLineWidth(0.5)
        canvas.line(25*mm, 18*mm, A4[0] - 25*mm, 18*mm)
        canvas.setFont("Courier", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(25*mm, 12*mm, f"ProbeThat — {hostname} — {scan_date}")
        canvas.drawRightString(A4[0] - 25*mm, 12*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)

    return output_path

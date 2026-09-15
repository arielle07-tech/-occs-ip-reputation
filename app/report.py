"""Generation du rapport PDF de synthese pour un lot d'IP analysees."""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

VERDICT_COLORS = {
    "MALVEILLANT": colors.HexColor("#c0392b"),
    "SUSPECT": colors.HexColor("#e67e22"),
    "SAIN": colors.HexColor("#27ae60"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=20, leading=24, spaceAfter=4,
        textColor=colors.HexColor("#FF7900"), alignment=TA_CENTER, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=10, leading=14,
        textColor=colors.HexColor("#555555"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontSize=13, leading=16, spaceBefore=6, spaceAfter=8,
        textColor=colors.white, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="Small", fontSize=8.5, leading=11, textColor=colors.HexColor("#333333"),
    ))
    return styles


def _summary_table(results: list[dict], styles) -> Table:
    header = ["Adresse IP", "Score", "Verdict", "AbuseIPDB", "VirusTotal", "Categories detectees"]
    rows = [header]
    for r in results:
        abuse = r["abuseipdb"]
        vt = r["virustotal"]
        abuse_txt = f'{abuse["abuse_confidence_score"]}% ({abuse.get("total_reports", 0)} signalements)' if abuse.get("available") else "N/A"
        vt_txt = f'{vt["malicious_engines"]}/{vt["total_engines"]} moteurs' if vt.get("available") else "N/A"
        cats = ", ".join(r["threat_categories"][:4]) if r["threat_categories"] else "Aucune"
        rows.append([
            r["ip"],
            f'{r["combined_score"]}/100',
            r["verdict"],
            abuse_txt,
            vt_txt,
            cats,
        ])

    col_widths = [2.6 * cm, 1.6 * cm, 2.3 * cm, 3.3 * cm, 2.8 * cm, 4.5 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FF7900")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f7")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, r in enumerate(results, start=1):
        color = VERDICT_COLORS.get(r["verdict"], colors.black)
        style_cmds.append(("TEXTCOLOR", (2, i), (2, i), color))
        style_cmds.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style_cmds))
    return table


def _detail_block(r: dict, styles) -> KeepTogether:
    abuse = r["abuseipdb"]
    vt = r["virustotal"]
    color = VERDICT_COLORS.get(r["verdict"], colors.black)

    heading_style = ParagraphStyle(
        "IPHeading", parent=styles["SectionHeading"], backColor=color,
    )
    elements = [
        Spacer(1, 10),
        Paragraph(f'&nbsp;{r["ip"]} — {r["verdict"]} ({r["combined_score"]}/100)&nbsp;', heading_style),
    ]

    lines = []
    if abuse.get("available"):
        lines.append(
            f'<b>AbuseIPDB</b> : score de confiance {abuse["abuse_confidence_score"]}%, '
            f'{abuse.get("total_reports", 0)} signalement(s), '
            f'pays {abuse.get("country_code") or "N/A"}, FAI {abuse.get("isp") or "N/A"}, '
            f'type {abuse.get("usage_type") or "N/A"}.'
        )
    else:
        lines.append(f'<b>AbuseIPDB</b> : indisponible ({abuse.get("error", "erreur inconnue")}).')

    if vt.get("available"):
        lines.append(
            f'<b>VirusTotal</b> : {vt["malicious_engines"]}/{vt["total_engines"]} moteurs '
            f'le signalent malveillant ({vt.get("suspicious_engines", 0)} suspects), '
            f'reputation {vt.get("reputation", 0)}, AS {vt.get("as_owner") or "N/A"}, '
            f'pays {vt.get("country") or "N/A"}.'
        )
    else:
        lines.append(f'<b>VirusTotal</b> : indisponible ({vt.get("error", "erreur inconnue")}).')

    if r["threat_categories"]:
        lines.append(f'<b>Menaces / categories detectees</b> : {", ".join(r["threat_categories"])}.')
    else:
        lines.append('<b>Menaces / categories detectees</b> : aucune categorie specifique remontee.')

    for line in lines:
        elements.append(Paragraph(line, styles["Small"]))
        elements.append(Spacer(1, 3))

    return KeepTogether(elements)


def generate_pdf_report(results: list[dict]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=1.8 * cm, bottomMargin=1.8 * cm, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
    )
    styles = _styles()
    story = []

    story.append(Paragraph("OCCS — Rapport d'analyse de reputation IP", styles["ReportTitle"]))
    now = datetime.now().strftime("%d/%m/%Y a %H:%M")
    story.append(Paragraph(
        f"Genere le {now} — {len(results)} adresse(s) IP analysee(s) — Sources : AbuseIPDB, VirusTotal",
        styles["ReportSubtitle"],
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Synthese", styles["SectionHeading"].clone("SynthHeading", textColor=colors.HexColor("#FF7900"))))
    story.append(_summary_table(results, styles))
    story.append(PageBreak())

    story.append(Paragraph("Details par adresse IP", styles["SectionHeading"].clone("DetailHeading", textColor=colors.HexColor("#FF7900"))))
    for r in results:
        story.append(_detail_block(r, styles))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()

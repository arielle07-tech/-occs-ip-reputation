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
    styles.add(ParagraphStyle(
        name="CellText", fontSize=8, leading=10.5, textColor=colors.HexColor("#222222"),
    ))
    styles.add(ParagraphStyle(
        name="CellHeader", fontSize=8, leading=10.5, textColor=colors.white, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="KVLabel", fontSize=8.5, leading=13, textColor=colors.HexColor("#666666"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="KVValue", fontSize=8.5, leading=13, textColor=colors.HexColor("#222222"),
    ))
    styles.add(ParagraphStyle(
        name="SourceHeading", fontSize=10.5, leading=14, spaceAfter=4,
        textColor=colors.HexColor("#FF7900"), fontName="Helvetica-Bold",
    ))
    return styles


def _summary_table(results: list[dict], styles) -> Table:
    header = ["Adresse IP", "Score", "Verdict", "AbuseIPDB", "VirusTotal", "Pays", "Fournisseur / AS"]
    rows = [[Paragraph(h, styles["CellHeader"]) for h in header]]
    for r in results:
        abuse = r["abuseipdb"]
        vt = r["virustotal"]
        abuse_txt = f'{abuse["abuse_confidence_score"]}%<br/>({abuse.get("total_reports", 0)} signal.)' if abuse.get("available") else "N/A"
        vt_txt = f'{vt["malicious_engines"]}/{vt["total_engines"]}<br/>moteurs' if vt.get("available") else "N/A"
        country_txt = r.get("country") or "N/A"
        provider_parts = []
        if r.get("network"):
            provider_parts.append(r["network"])
        if r.get("asn"):
            provider_parts.append(f'AS{r["asn"]}')
        provider_txt = " · ".join(provider_parts) if provider_parts else "N/A"
        if r.get("as_owner"):
            provider_txt += f' ({r["as_owner"]})'

        verdict_style = ParagraphStyle(
            f'Verdict{r["ip"].replace(".", "_")}', parent=styles["CellText"],
            textColor=VERDICT_COLORS.get(r["verdict"], colors.black), fontName="Helvetica-Bold",
        )
        rows.append([
            Paragraph(r["ip"], styles["CellText"]),
            Paragraph(f'{r["combined_score"]}/100', styles["CellText"]),
            Paragraph(r["verdict"], verdict_style),
            Paragraph(abuse_txt, styles["CellText"]),
            Paragraph(vt_txt, styles["CellText"]),
            Paragraph(country_txt, styles["CellText"]),
            Paragraph(provider_txt, styles["CellText"]),
        ])

    col_widths = [2.6 * cm, 1.5 * cm, 2.6 * cm, 2.5 * cm, 1.9 * cm, 1.3 * cm, 4.7 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FF7900")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f7")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    table.setStyle(TableStyle(style_cmds))
    return table


def _kv_table(pairs: list[tuple[str, str]], styles) -> Table:
    rows = [[Paragraph(label, styles["KVLabel"]), Paragraph(str(value), styles["KVValue"])] for label, value in pairs]
    table = Table(rows, colWidths=[3.0 * cm, 5.5 * cm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
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
        Spacer(1, 8),
    ]

    if abuse.get("available"):
        abuse_pairs = [
            ("Score de confiance", f'{abuse["abuse_confidence_score"]}%'),
            ("Signalements", str(abuse.get("total_reports", 0))),
            ("Pays", abuse.get("country_code") or "N/A"),
            ("FAI", abuse.get("isp") or "N/A"),
            ("Type", abuse.get("usage_type") or "N/A"),
        ]
        abuse_col = [Paragraph("AbuseIPDB", styles["SourceHeading"]), _kv_table(abuse_pairs, styles)]
    else:
        abuse_col = [
            Paragraph("AbuseIPDB", styles["SourceHeading"]),
            Paragraph(f'Indisponible ({abuse.get("error", "erreur inconnue")}).', styles["KVValue"]),
        ]

    if vt.get("available"):
        vt_pairs = [
            ("Moteurs malveillants", f'{vt["malicious_engines"]}/{vt["total_engines"]}'),
            ("Moteurs suspects", str(vt.get("suspicious_engines", 0))),
            ("Reputation", str(vt.get("reputation", 0))),
            ("Reseau (CIDR)", vt.get("network") or "N/A"),
            ("ASN", f'AS{vt.get("asn")}' if vt.get("asn") else "N/A"),
            ("Fournisseur", vt.get("as_owner") or "N/A"),
            ("Pays", vt.get("country") or "N/A"),
        ]
        vt_col = [Paragraph("VirusTotal", styles["SourceHeading"]), _kv_table(vt_pairs, styles)]
    else:
        vt_col = [
            Paragraph("VirusTotal", styles["SourceHeading"]),
            Paragraph(f'Indisponible ({vt.get("error", "erreur inconnue")}).', styles["KVValue"]),
        ]

    two_col = Table([[abuse_col, vt_col]], colWidths=[8.7 * cm, 8.7 * cm])
    two_col.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(two_col)
    elements.append(Spacer(1, 4))
    elements.append(Table([[""]], colWidths=[17.4 * cm], style=TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ])))

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

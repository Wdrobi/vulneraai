"""
VulneraAI - Report Generator Service
"""

import json
from datetime import datetime
from io import BytesIO

try:
    # Prefer reportlab for reliable PDF generation
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm, cm
    from reportlab.pdfgen import canvas
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

class ReportGenerator:
    def __init__(self, scan):
        self.scan = scan

    def generate_json(self):
        """Generate JSON report"""
        report = {
            'metadata': {
                'reportId': self.scan.id,
                'generatedAt': datetime.utcnow().isoformat(),
                'target': self.scan.target,
                'scanType': self.scan.scan_type,
                'status': self.scan.status
            },
            'summary': {
                'riskScore': self.scan.risk_score,
                'riskLevel': self.scan.risk_level,
                'totalVulnerabilities': len(self.scan.vulnerabilities),
                'stats': {
                    'critical': sum(1 for v in self.scan.vulnerabilities if v.severity == 'critical'),
                    'high': sum(1 for v in self.scan.vulnerabilities if v.severity == 'high'),
                    'medium': sum(1 for v in self.scan.vulnerabilities if v.severity == 'medium'),
                    'low': sum(1 for v in self.scan.vulnerabilities if v.severity == 'low')
                }
            },
            'vulnerabilities': [v.to_dict() for v in self.scan.vulnerabilities],
            'timestamps': {
                'startedAt': self.scan.created_at.isoformat() if self.scan.created_at else None,
                'completedAt': self.scan.completed_at.isoformat() if self.scan.completed_at else None
            }
        }

        return json.dumps(report, indent=2)

    def generate_pdf(self):
        """Generate PDF report bytes matching HTML template design.
        Creates professional multi-page PDF with hero, meta, risk summary, and vulnerabilities.
        """
        if REPORTLAB_AVAILABLE:
            from reportlab.lib.styles import ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.lib import colors as rl_colors
            from reportlab.graphics import renderPM
            import os
            # Optional: svglib for SVG rendering
            try:
                from svglib.svglib import svg2rlg
                SVGLIB_AVAILABLE = True
            except Exception:
                SVGLIB_AVAILABLE = False
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=15*mm, 
                                   leftMargin=20*mm, rightMargin=20*mm)
            
            story = []
            
            # Get scan data
            risk_level = getattr(self.scan, 'risk_level', 'Unknown')
            risk_score = getattr(self.scan, 'risk_score', 0)
            vulns = self.scan.vulnerabilities or []
            
            # Count vulnerabilities by severity
            sev_counts = {
                'critical': sum(1 for v in vulns if (v.severity or '').lower() == 'critical'),
                'high': sum(1 for v in vulns if (v.severity or '').lower() == 'high'),
                'medium': sum(1 for v in vulns if (v.severity or '').lower() == 'medium'),
                'low': sum(1 for v in vulns if (v.severity or '').lower() == 'low'),
                'info': sum(1 for v in vulns if (v.severity or '').lower() == 'info'),
            }
            
            # ===== HEADER WITH LOGO =====
            logo_path = os.path.join(os.path.dirname(__file__), '../../frontend/assets/logo.svg')

            # Header styles with improved leading/spacing
            header_title_style = ParagraphStyle('HeaderTitle', fontName='Helvetica-Bold', fontSize=22,
                                               textColor=rl_colors.HexColor('#0f172a'), leading=26, spaceAfter=6)
            header_subtitle = ParagraphStyle('HeaderSubtitle', fontName='Helvetica', fontSize=10,
                                            textColor=rl_colors.HexColor('#64748b'), leading=12)

            # Render SVG logo to PNG (in-memory) if svglib is available
            logo_flowable = None
            if SVGLIB_AVAILABLE and os.path.exists(logo_path):
                try:
                    drawing = svg2rlg(logo_path)
                    png_bytes = renderPM.drawToString(drawing, fmt='PNG')
                    # Reduce logo size to avoid overlapping the title
                    logo_flowable = Image(BytesIO(png_bytes), width=28*mm, height=14*mm)
                except Exception:
                    logo_flowable = None

            # Fallback logo text if SVG cannot be rendered
            if logo_flowable is None:
                logo_text_style = ParagraphStyle('LogoText', fontName='Helvetica-Bold', fontSize=18,
                                                textColor=rl_colors.HexColor('#dc2626'))
                logo_flowable = Paragraph('VulneraAI', logo_text_style)

            # Title block
            title_para = Paragraph('Security Assessment<br/>Vulnerability Scan Report', header_title_style)

            # Right header (risk chip + meta)
            def risk_chip(level):
                lvl = (level or 'LOW').upper()
                color_map = {
                    'CRITICAL': rl_colors.HexColor('#ef4444'),
                    'HIGH': rl_colors.HexColor('#f59e0b'),
                    'MEDIUM': rl_colors.HexColor('#eab308'),
                    'LOW': rl_colors.HexColor('#22c55e'),
                    'INFO': rl_colors.HexColor('#38bdf8'),
                }
                bg = color_map.get(lvl, rl_colors.HexColor('#22c55e'))
                chip = Table([[Paragraph(f'<b>{lvl} RISK</b>', ParagraphStyle('ChipText', fontName='Helvetica-Bold', fontSize=9, textColor=rl_colors.white, alignment=TA_CENTER))]], colWidths=[30*mm])
                chip.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, 0), bg),
                    ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                    ('VALIGN', (0, 0), (0, 0), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (0, 0), 6),
                    ('RIGHTPADDING', (0, 0), (0, 0), 6),
                    ('TOPPADDING', (0, 0), (0, 0), 3),
                    ('BOTTOMPADDING', (0, 0), (0, 0), 3),
                ]))
                return chip

            right_meta_style = ParagraphStyle('RightMeta', fontName='Helvetica', fontSize=9, textColor=rl_colors.HexColor('#64748b'))
            right_block = [risk_chip(risk_level), Spacer(1, 4), Paragraph(f'Scan ID: {self.scan.id}', right_meta_style), Paragraph(f'Prepared for: {getattr(self.scan, 'user_id', 'Authenticated User')}', right_meta_style)]

            right_table = Table([[right_block[0]], [right_block[1]], [right_block[2]], [right_block[3]]], colWidths=[50*mm])
            right_table.setStyle(TableStyle([
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))

            # Assemble header table (logo + titles) | (risk chip + meta)
            # Increase the logo column width so it matches the image width
            header_table = Table([[logo_flowable, title_para, right_table]], colWidths=[34*mm, 86*mm, 50*mm])
            header_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(header_table)
            story.append(Paragraph('Prepared by VulneraAI Security Team', header_subtitle))
            story.append(Spacer(1, 12))
            
            # ===== META INFORMATION =====
            meta_style = ParagraphStyle('MetaLabel', fontName='Helvetica-Bold', fontSize=9, 
                                       textColor=rl_colors.HexColor('#64748b'))
            meta_value_style = ParagraphStyle('MetaValue', fontName='Helvetica-Bold', fontSize=11, 
                                             textColor=rl_colors.HexColor('#0f172a'))
            
            meta_title = ParagraphStyle('MetaTitle', fontName='Helvetica-Bold', fontSize=12,
                                       spaceAfter=8, textColor=rl_colors.HexColor('#0f172a'), leading=14)
            story.append(Paragraph("Scan Details", meta_title))
            
            meta_data = [
                ['Target:', self.scan.target],
                ['Scan Date:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
                ['Total Findings:', str(len(vulns))],
                ['Assessor:', 'VulneraAI Automated Scanner']
            ]
            
            meta_table = Table(meta_data, colWidths=[4*cm, 12.5*cm])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), rl_colors.HexColor('#f0f4f8')),
                ('BACKGROUND', (1, 0), (1, -1), rl_colors.HexColor('#ffffff')),
                ('TEXTCOLOR', (0, 0), (-1, -1), rl_colors.HexColor('#0f172a')),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, rl_colors.HexColor('#e2e8f0')),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 18))
            
            # ===== RISK SUMMARY =====
            risk_title = ParagraphStyle('SectionTitle', fontName='Helvetica-Bold', fontSize=12,
                                       spaceAfter=10, textColor=rl_colors.HexColor('#0f172a'))
            story.append(Paragraph('Risk Overview', risk_title))

            # Circular gauge
            try:
                from reportlab.graphics.shapes import Drawing, Circle, Wedge, String
                gauge = Drawing(120, 80)
                # Background circle
                gauge.add(Circle(40, 40, 28, strokeColor=rl_colors.HexColor('#e5e7eb'), fillColor=None, strokeWidth=6))
                # Score wedge
                angle = int((risk_score/100.0) * 360)
                gauge.add(Wedge(40, 40, 28, 90, 90+angle, fillColor=rl_colors.HexColor('#60a5fa'), strokeColor=None))
                # Inner circle
                gauge.add(Circle(40, 40, 20, strokeColor=None, fillColor=rl_colors.HexColor('#ffffff')))
                # Text
                gauge.add(String(36, 34, str(int(risk_score)), fontName='Helvetica-Bold', fontSize=12, fillColor=rl_colors.HexColor('#0f172a')))
                gauge.add(String(64, 36, f'{risk_level}'.upper(), fontName='Helvetica-Bold', fontSize=10, fillColor=rl_colors.HexColor('#64748b')))
            except Exception:
                gauge = Paragraph(f'<b>{risk_score}</b> / 100 ({risk_level})', ParagraphStyle('GaugeFallback', fontName='Helvetica', fontSize=10))

            # Severity cards
            sev_cards = Table([
                [
                    Table([[Paragraph('Critical', ParagraphStyle('sc1', fontName='Helvetica-Bold', fontSize=9)), Paragraph(str(sev_counts['critical']), ParagraphStyle('scv1', fontName='Helvetica-Bold', fontSize=11))]], colWidths=[25*mm, 12*mm]),
                    Table([[Paragraph('High', ParagraphStyle('sc2', fontName='Helvetica-Bold', fontSize=9)), Paragraph(str(sev_counts['high']), ParagraphStyle('scv2', fontName='Helvetica-Bold', fontSize=11))]], colWidths=[25*mm, 12*mm]),
                    Table([[Paragraph('Medium', ParagraphStyle('sc3', fontName='Helvetica-Bold', fontSize=9)), Paragraph(str(sev_counts['medium']), ParagraphStyle('scv3', fontName='Helvetica-Bold', fontSize=11))]], colWidths=[25*mm, 12*mm]),
                    Table([[Paragraph('Low', ParagraphStyle('sc4', fontName='Helvetica-Bold', fontSize=9)), Paragraph(str(sev_counts['low']), ParagraphStyle('scv4', fontName='Helvetica-Bold', fontSize=11))]], colWidths=[25*mm, 12*mm]),
                ]
            ], colWidths=[37*mm, 37*mm, 37*mm, 37*mm])
            sev_cards.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), rl_colors.HexColor('#fee2e2')),
                ('BACKGROUND', (1, 0), (1, 0), rl_colors.HexColor('#fde68a')),
                ('BACKGROUND', (2, 0), (2, 0), rl_colors.HexColor('#fef3c7')),
                ('BACKGROUND', (3, 0), (3, 0), rl_colors.HexColor('#dcfce7')),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))

            risk_block = Table([[gauge, sev_cards]], colWidths=[45*mm, 103*mm])
            risk_block.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(risk_block)
            story.append(Spacer(1, 12))
            
            # ===== RECOMMENDATIONS =====
            story.append(Paragraph("Top Recommendations", risk_title))
            
            recommendations = [v.remediation for v in vulns if getattr(v, 'remediation', None)][:4]
            if not recommendations:
                recommendations = [
                    'Implement secure configuration baselines and retest.',
                    'Ensure timely patching of exposed services.',
                    'Harden network access with least privilege rules.',
                    'Monitor and log security-relevant events continuously.'
                ]
            
            for idx, rec in enumerate(recommendations, 1):
                rec_style = ParagraphStyle('Recommendation', fontName='Helvetica', fontSize=10,
                                          leftIndent=20, spaceAfter=6)
                story.append(Paragraph(f"<b>{idx}.</b> {rec[:200]}", rec_style))
            
            story.append(Spacer(1, 20))
            story.append(PageBreak())
            
            # ===== DETAILED FINDINGS =====
            story.append(Paragraph("Detailed Findings", risk_title))
            story.append(Spacer(1, 10))
            
            if not vulns:
                no_vuln_style = ParagraphStyle('NoVuln', fontName='Helvetica', fontSize=12,
                                              textColor=rl_colors.HexColor('#666'))
                story.append(Paragraph("✓ No vulnerabilities found", no_vuln_style))
            else:
                for idx, v in enumerate(vulns, 1):
                    # Vulnerability title with severity
                    severity = (v.severity or 'unknown').upper()
                    severity_color = {
                        'CRITICAL': rl_colors.HexColor('#ff6b6b'),
                        'HIGH': rl_colors.HexColor('#ffa500'),
                        'MEDIUM': rl_colors.HexColor('#ffc107'),
                        'LOW': rl_colors.HexColor('#28a745'),
                        'INFO': rl_colors.HexColor('#0369a1'),
                    }.get(severity, rl_colors.HexColor('#0f172a'))
                    
                    vuln_title_style = ParagraphStyle('VulnTitle', fontName='Helvetica-Bold', 
                                                     fontSize=11, spaceAfter=6, 
                                                     textColor=rl_colors.HexColor('#1a1a1a'),
                                                     leftIndent=0)
                    
                    # Severity badge
                    severity_color = {
                        'CRITICAL': '#dc2626',
                        'HIGH': '#f97316',
                        'MEDIUM': '#eab308',
                        'LOW': '#16a34a',
                        'INFO': '#0284c7',
                    }.get(severity, '#6b7280')
                    
                    story.append(Paragraph(f"<b>{idx}. {v.title}</b> <font color='{severity_color}' size=9><b>▪ {severity}</b></font>", vuln_title_style))
                    
                    # Description
                    desc_style = ParagraphStyle('Description', fontName='Helvetica', fontSize=9,
                                               leftIndent=15, spaceAfter=8,
                                               textColor=rl_colors.HexColor('#555'),
                                               leading=11)
                    if getattr(v, 'description', None):
                        story.append(Paragraph(v.description[:300], desc_style))
                    
                    # Details table
                    details = []
                    if v.port:
                        details.append(('Port:', str(v.port)))
                    if v.service:
                        details.append(('Service:', v.service))
                    if v.cve:
                        details.append(('CVE ID:', v.cve))
                    
                    if details:
                        story.append(Spacer(1, 4))
                        detail_table = Table(details, colWidths=[2.8*cm, 12*cm])
                        detail_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), rl_colors.HexColor('#f3f4f6')),
                            ('BACKGROUND', (1, 0), (1, -1), rl_colors.HexColor('#ffffff')),
                            ('TEXTCOLOR', (0, 0), (-1, -1), rl_colors.HexColor('#333')),
                            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                            ('TOPPADDING', (0, 0), (-1, -1), 5),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 0.5, rl_colors.HexColor('#e5e7eb')),
                        ]))
                        story.append(detail_table)
                    
                    # Remediation
                    if getattr(v, 'remediation', None):
                        story.append(Spacer(1, 6))
                        rem_style = ParagraphStyle('Remediation', fontName='Helvetica', fontSize=9,
                                                  leftIndent=15, spaceAfter=10, leading=11,
                                                  textColor=rl_colors.HexColor('#1f2937'))
                        story.append(Paragraph(f"<b>Remediation:</b> {v.remediation[:250]}", rem_style))
                    
                    story.append(Spacer(1, 14))
                    
                    # Page break every 5 vulnerabilities
                    if idx % 5 == 0 and idx < len(vulns):
                        story.append(PageBreak())
            
            # ===== FOOTER =====
            story.append(Spacer(1, 20))
            footer_style = ParagraphStyle('Footer', fontName='Helvetica', fontSize=8,
                                         textColor=rl_colors.HexColor('#64748b'),
                                         alignment=TA_CENTER)
            story.append(Paragraph("This report contains sensitive security information. Handle with care.<br/>" +
                                 f"Generated by VulneraAI on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", 
                                 footer_style))
            
            # Build PDF
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes
        
        # Fallback minimal PDF
        pdf_content = f"""
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< >>
stream
BT
/F1 12 Tf
50 700 Td
(VulneraAI - Vulnerability Scan Report) Tj
0 -30 Td
(Target: {self.scan.target}) Tj
0 -20 Td
(Risk Score: {getattr(self.scan,'risk_score',0)}/100 - {getattr(self.scan,'risk_level','Unknown')}) Tj
0 -20 Td
(Vulnerabilities Found: {len(self.scan.vulnerabilities)}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000245 00000 n 
0000000456 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
535
%%EOF
"""
        # Return bytes for consistency
        return pdf_content.encode('latin-1')

    def generate_csv(self):
        """Generate CSV report"""
        csv = 'Title,Severity,Port,Service,CVE,Description,Remediation\n'
        
        for vuln in self.scan.vulnerabilities:
            row = f'"{vuln.title}","{vuln.severity}",{vuln.port},"{vuln.service}","{vuln.cve}","{vuln.description}","{vuln.remediation}"\n'
            csv += row

        return csv

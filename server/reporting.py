import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_incident_report(alert):
    """
    Generates a PDF incident report for a specific ransomware alert.
    Returns the PDF as an io.BytesIO object.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    title_style.alignment = 1 # Center
    
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Custom styles
    alert_style = ParagraphStyle(
        'AlertStyle',
        parent=styles['Normal'],
        textColor=colors.red if alert.severity == 'CRITICAL' else colors.orange,
        fontName='Helvetica-Bold'
    )
    
    elements = []
    
    # Title
    elements.append(Paragraph("REWARS Incident Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Summary Section
    elements.append(Paragraph("Incident Summary", heading_style))
    elements.append(Spacer(1, 6))
    
    summary_data = [
        ["Alert ID:", str(alert.id)],
        ["Timestamp:", alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')],
        ["Severity:", Paragraph(alert.severity, alert_style)],
        ["Type:", alert.alert_type],
    ]
    
    summary_table = Table(summary_data, colWidths=[100, 300])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 24))
    
    # Agent Details Section
    elements.append(Paragraph("Affected Endpoint Details", heading_style))
    elements.append(Spacer(1, 6))
    
    if alert.agent:
        agent_data = [
            ["Agent ID:", alert.agent_id],
            ["Hostname:", alert.agent.hostname],
            ["IP Address:", alert.agent.ip_address],
            ["Agent Status:", alert.agent.status],
        ]
    else:
        agent_data = [
            ["Agent ID:", alert.agent_id],
            ["Warning:", "Agent details not found in database"],
        ]
        
    agent_table = Table(agent_data, colWidths=[100, 300])
    agent_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(agent_table)
    elements.append(Spacer(1, 24))
    
    # Technical Details Section
    elements.append(Paragraph("Technical Details", heading_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Description: {alert.description}", normal_style))
    
    # Footer
    elements.append(Spacer(1, 48))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], alignment=1, textColor=colors.grey)
    elements.append(Paragraph(f"Report generated automatically by REWARS on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer

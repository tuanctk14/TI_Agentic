from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import pandas as pd

def generate_daily_report(iocs: list, matches: list, output_path: str = None):
    """Tạo báo cáo PDF hàng ngày"""
    
    date_str = datetime.now().strftime("%Y-%m-%d")
    if not output_path:
        output_path = f"reports/daily_report_{date_str}.pdf"
    
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Tiêu đề
    story.append(Paragraph(
        f"Báo cáo Threat Intelligence - {date_str}", 
        styles['Title']
    ))
    
    # Tóm tắt
    story.append(Paragraph("📊 Tóm tắt", styles['Heading2']))
    summary_data = [
        ["Chỉ số", "Giá trị"],
        ["Tổng IOC thu thập", str(len(iocs))],
        ["IOC rủi ro cao/critical", 
         str(len([i for i in iocs if i.get('risk_level') in ['high','critical']]))],
        ["Thiết bị bị ảnh hưởng", 
         str(len(set(m['asset_hostname'] for m in matches)))],
    ]
    
    table = Table(summary_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTSIZE', (0,0), (-1,-1), 10),
    ]))
    story.append(table)
    
    doc.build(story)
    print(f"✅ Báo cáo đã tạo: {output_path}")
    return output_path

def schedule_reports():
    """Lên lịch tạo báo cáo tự động"""
    from apscheduler.schedulers.background import BackgroundScheduler
    
    scheduler = BackgroundScheduler()
    
    # Báo cáo hàng ngày lúc 8 giờ sáng
    scheduler.add_job(
        func=lambda: generate_daily_report([], []),  
        trigger='cron', hour=8, minute=0,
        id='daily_report'
    )
    
    # Báo cáo hàng tuần thứ 2
    scheduler.add_job(
        func=lambda: generate_daily_report([], []),
        trigger='cron', day_of_week='mon', hour=8,
        id='weekly_report'
    )
    
    scheduler.start()
    return scheduler
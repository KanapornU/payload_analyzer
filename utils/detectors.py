'''
payload_analyzer/
- analyzer.py               # โค้ดหลัก ควบคุมการยิง payload
- utils/
    - detectors.py          # รวมฟังก์ชันวิเคราะห์ผลลัพธ์
- payloads/
    - xss.json              # รายการ payload
- targets/
    - testsite.json         # รายการ target site
- results/
    - report.json
    - report.csv

ฟังก์ชันวิเคราะห์ผลลัพธ์ใน detectors.py 
- วิเคราะห์ความเสี่ยง/ช่องโหว่ ตรวจสอบว่าเว็บเป้าหมาย มีจุดอ่อน เช่น XSS หรือ SQLi หรือไม่
- ใช้สร้างรายงานอัตโนมัติ ทำให้เราสร้าง รายงานช่องโหว่ เพื่อใช้ใน Pentest report, Dashboard ระบบ, แจ้งเตือนทีม Dev/IT
- ใช้ในการ Trigger การแจ้งเตือน ถ้าพบ verdict เช่น Possible Time-Based SQLi หรือ Reflected
'''

# ฟังก์ชันสำหรับวิเคราะห์ผลลัพธ์ของ HTTP response ที่ได้จากการยิง payload
def analyze_response(payload, response, delay): 
    # ดึง HTTP status code เช่น 200, 403, 500
    status = response.status_code

    # ดึงเนื้อหาใน response (HTML/ข้อความ)
    content = response.text

    # ตรวจสอบว่า payload ปรากฏอยู่ใน response หรือไม่ (เช่น ใช้ตรวจ reflected XSS)
    reflected = payload in content

    # เริ่มกำหนด verdict (คำตัดสิน)
    if status == 403:
        # หากเซิร์ฟเวอร์บล็อก request เลย (Forbidden)
        verdict = "Blocked"
    elif status == 500:
        # หากเกิด error ฝั่งเซิร์ฟเวอร์ (Internal Server Error)
        verdict = "Server Error"
    elif delay > 3:
        # หาก response ช้ากว่าปกติมาก อาจบ่งชี้ว่าโดน time-based SQL injection
        verdict = "Possible Time-Based SQLi"
    elif reflected:
        # ถ้า payload โผล่ใน response แปลว่า injected สำเร็จ
        verdict = "Delivered"
    else:
        # ไม่เข้าเงื่อนไขใดเลย อาจถูกกรองหรือมีพฤติกรรมน่าสงสัย
        verdict = "Suspicious or Filtered"

    # ส่งคืนผลลัพธ์เป็น dictionary ที่ใช้เก็บในรายงาน
    return {
        "payload": payload,       # Payload ที่ส่งไป
        "status": status,         # HTTP status code ที่ได้
        "reflected": reflected,   # มี payload โผล่ใน response หรือไม่
        "delay": delay,           # ระยะเวลาที่ใช้ใน request
        "verdict": verdict        # ข้อสรุปว่าผลลัพธ์นี้หมายถึงอะไร
    }

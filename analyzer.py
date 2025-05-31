'''
เครื่องมือวิเคราะห์ Payload อัตโนมัติ สำหรับทดสอบช่องโหว่เว็บ เช่น XSS, SQLi โดยการส่ง payload ไปยัง target URL แล้ววิเคราะห์ผลลัพธ์ที่ได้รับ

- ส่ง payload ไปยัง URL จากลิสต์ target 
- ตรวจว่า payload ถูก "สะท้อน", "บล็อก", หรือ "รันสำเร็จ"
- วิเคราะห์สถานะ เช่น 403, 500, delay สูง
- สร้างรายงาน .json และ .csv
- สรุปผล: ผ่าน / บล็อก / น่าสงสัย
'''

# นำเข้าโมดูลที่จำเป็น
import json         # ใช้โหลด/บันทึกไฟล์ JSON
import time         # ใช้วัดเวลาการตอบกลับ (delay)
import requests     # ใช้ส่ง HTTP requests
import os           # ใช้จัดการไฟล์และโฟลเดอร์
import csv          # ใช้บันทึกผลลัพธ์ลง CSV
from utils.detectors import analyze_response  # ฟังก์ชันวิเคราะห์ผลลัพธ์ที่กำหนดเอง

# โหลด payloads สำหรับทดสอบ XSS จากไฟล์ JSON
with open("payloads/xss.json", "r", encoding="utf-8") as f:
    payloads = json.load(f)

# โหลดรายชื่อ target จากไฟล์ JSON (ประกอบด้วย URL, method, body ฯลฯ)
with open("targets/testsite.json", "r", encoding="utf-8") as f:
    targets = json.load(f)

# รายการเก็บผลลัพธ์ที่ได้จากการยิง payloads
results = []

# วนลูป payloads ทุกอัน
for payload in payloads:
    # วนลูป target ทุกอัน
    for target in targets:
        # สร้าง URL โดยแทนที่คำว่า "PAYLOAD" ด้วย payload จริง
        url = target["url"].replace("PAYLOAD", payload)

        # ดึง method (GET หรือ POST) ถ้าไม่มีระบุให้ใช้ GET เป็นค่า default
        method = target.get("method", "GET").upper()

        # สร้าง body (สำหรับ POST) โดยแทนที่ "PAYLOAD" ถ้ามี
        data = target.get("body", "").replace("PAYLOAD", payload)

        try:
            # เริ่มจับเวลาเพื่อวัด delay
            start = time.time()

            # ส่ง request ตาม method ที่ระบุ
            if method == "POST":
                res = requests.post(url, data=data, timeout=10)
            else:
                res = requests.get(url, timeout=10)

            # วัดเวลาที่ใช้ (delay)
            delay = round(time.time() - start, 2)
            
            # วิเคราะห์ผลลัพธ์ด้วยฟังก์ชัน custom
            analysis = analyze_response(payload, res, delay)

            # เพิ่ม target URL ลงในผลลัพธ์
            analysis["target"] = url

            # บันทึกผลลัพธ์
            results.append(analysis)
            
        # ถ้าเกิด error ระหว่าง request เช่น timeout, DNS fail, ฯลฯ    
        except Exception as e:
            results.append({
                "payload": payload,
                "target": url,
                "status": "ERROR",
                "reflected": False,
                "delay": 0,
                "verdict": str(e)  # เก็บข้อความ error ไว้ใน verdict
            })

# สร้างโฟลเดอร์เก็บผลลัพธ์ ถ้ายังไม่มี
os.makedirs("results", exist_ok=True)

# บันทึกผลลัพธ์ลงไฟล์ JSON
with open("results/report.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# บันทึกผลลัพธ์ลงไฟล์ CSV
with open("results/report.csv", "w", newline='', encoding="utf-8") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["payload", "target", "status", "reflected", "delay", "verdict"])
    writer.writeheader()           # เขียนหัวตาราง
    writer.writerows(results)      # เขียนข้อมูลแต่ละแถว

# สรุปผลลัพธ์แบบสั้นๆ แสดงจำนวน payloads ที่ตรวจพบ
print("\n Summary:")

# เงื่อนไขว่าผ่าน: status 200 และตรวจพบ reflected หรือ delivered
passed = [r for r in results if r["status"] == 200 and (r["reflected"] or r["verdict"] == "Delivered")]

# เงื่อนไขว่าถูกบล็อก: status 403 หรือ verdict เป็น Blocked
blocked = [r for r in results if r["status"] == 403 or r["verdict"] == "Blocked"]

# เงื่อนไขว่าน่าสงสัย: delay > 3 วินาที หรือ verdict เริ่มด้วย "possible"
suspicious = [r for r in results if r["delay"] > 3 or r["verdict"].lower().startswith("possible")]

# แสดงจำนวนแต่ละประเภท
print(f"Passed Payloads: {len(passed)}")
print(f"Blocked Payloads: {len(blocked)}")
print(f"Suspicious Payloads: {len(suspicious)}")

# แสดงตัวอย่าง payload ที่น่าสงสัย 3 รายการแรก
print("\nExample Suspicious:")
for s in suspicious[:3]:
    print(f"- {s['payload']} → {s['verdict']}")

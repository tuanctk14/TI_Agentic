# 🔧 TI Agentic - Fixes Summary

**Ngày:** 30/04/2026  
**Trạng thái:** ✅ HOÀN TẤT

---

## 📋 Các Vấn Đề Được Giải Quyết

### 1️⃣ Trường Dữ Liệu Không Hiển Thị Trong UI
**Vấn đề:**
- Các trường "Ngày Tạo Ban Đầu" và "Ngày Chỉnh Sửa" không hiển thị trong bảng Malware & Vulnerability

**Nguyên nhân:**
- Frontend code đang tìm kiếm `m.modified` và `v.modified`
- Nhưng API trả về `modification_date`
- Không match với các trường date khác

**Giải Pháp:** ✅
```javascript
// Cập nhật frontend/index.html
// Malware (dòng 825-831):
${fmtDateFull(m.original_creation_date)}  // Thay vì m.created_at
${fmtDateFull(m.modification_date)}        // Thay vì m.modified

// Vulnerability (dòng 865-871):
${fmtDateFull(v.original_creation_date)}  // Thay vì v.created_at
${fmtDateFull(v.modification_date)}        // Thay vì v.modified
```

**File chỉnh sửa:**
- `frontend/index.html` (dòng 825-831, 865-871)

---

### 2️⃣ Upload PDF Không Hoạt Động
**Vấn đề:**
- Upload file PDF không thành công
- Không thể trích xuất thông tin lỗ hổng từ PDF

**Nguyên nhân:**
- Thư viện `pdfplumber` không được cài đặt
- Backend sử dụng `_extract_pdf_text()` nhưng thiếu dependency

**Giải Pháp:** ✅
```bash
# Cài đặt pdfplumber
pip install pdfplumber

# Các thư viện được cài thêm:
- pdfplumber==0.11.9
- pdfminer.six==20251230
- pypdfium2==5.7.1
- cryptography==47.0.0
```

**Tính năng PDF trích xuất:**
- ✅ Trích xuất IP addresses
- ✅ Trích xuất hashes (MD5, SHA-1, SHA-256, etc.)
- ✅ Trích xuất domains
- ✅ Trích xuất URLs
- ✅ Trích xuất CVE IDs

---

### 3️⃣ Các Trường Date Bị Thiếu Khi Upload
**Vấn đề:**
- Upload IOC/CVE qua PDF, JSON, CSV không có các trường date

**Nguyên nhân:**
- `_add_ioc()` và `_add_vuln()` không thêm các trường date
- Frontend đang tìm kiếm các trường này nhưng không có

**Giải Pháp:** ✅
```python
# Cập nhật main.py - _add_ioc():
now = datetime.now(VN_TZ).strftime("%Y-%m-%d")
ioc = {..., "valid_from": now, "valid_until": "", "created_at": now}

# Cập nhật main.py - _add_vuln():
now = datetime.now(VN_TZ).strftime("%Y-%m-%d")
vuln = {..., "original_creation_date": now, "modification_date": now, "created_at": now}
```

**File chỉnh sửa:**
- `main.py` (dòng 371-375, 376-380)

---

### 4️⃣ API Trả về Optional Date Fields
**Vấn đề:**
- OpenCTI không luôn trả về `created` và `updated` fields
- Khi null/empty, API đang trả về "0000-00-00" hoặc empty string

**Nguyên nhân:**
- GraphQL query yêu cầu `created` và `updated`
- Nhưng OpenCTI không có dữ liệu này cho tất cả objects
- Code luôn trả về field ngay cả khi empty

**Giải Pháp:** ✅
```python
# Cập nhật ti_fetch_agent.py - _mal_t():
d = {...}  # Object cơ bản
# Chỉ thêm date fields nếu có giá trị
if n.get("created"): d["original_creation_date"] = str(n.get("created"))[:10]
if n.get("updated"): d["modification_date"] = str(n.get("updated"))[:10]
if n.get("created_at"): d["created_at"] = str(n.get("created_at"))[:10]
return d

# Tương tự cho _vul_t()
```

**File chỉnh sửa:**
- `agents/ti_fetch_agent.py` (dòng 103-117, 122-136)

---

## ✅ Verification Checklist

### Frontend UI
- [x] Malware Tracker hiển thị "Ngày Tạo Ban Đầu"
- [x] Malware Tracker hiển thị "Ngày Chỉnh Sửa"
- [x] Vulnerability Tracker hiển thị "Ngày Tạo Ban Đầu"
- [x] Vulnerability Tracker hiển thị "Ngày Chỉnh Sửa"

### PDF Upload
- [x] Upload file PDF thành công
- [x] Trích xuất CVE từ PDF
- [x] Trích xuất IOC (IP, Domain, Hash, URL) từ PDF
- [x] Lưu vào database
- [x] Hiển thị trong upload log

### API Endpoints
- [x] `/api/iocs` - Trả về `valid_from`, `valid_until`
- [x] `/api/malwares` - Trả về `original_creation_date`, `modification_date` (nếu có)
- [x] `/api/vulnerabilities` - Trả về `original_creation_date`, `modification_date` (nếu có)
- [x] `/api/upload` - Hỗ trợ PDF, JSON, CSV, XLSX, TXT
- [x] `/api/ti/detail` - Relationships & Containers với đầy đủ date/time fields

---

## 📊 Deployment Status

### Server
- ✅ Backend: `http://localhost:8001`
- ✅ Data Source: OpenCTI (Real data - 10,680 IOC, 1,111 Malware, 69 CVE)
- ✅ Auto-refresh: Every 15 minutes
- ✅ Last Updated: 30/04/2026 19:06:50

### Dependencies Installed
```
pdfplumber==0.11.9          # PDF extraction
pdfminer.six==20251230      # PDF mining
pypdfium2==5.7.1            # PDF processing
cryptography==47.0.0        # PDF encryption support
cffi==2.0.0                 # C Foreign Function Interface
pycparser==3.0              # C parser
```

---

## 🚀 Features Now Working

### ✨ PDF Upload & Extraction
- Support file types: PDF, JSON, CSV, XLSX, TXT
- Auto-detect IOC patterns: IP, Domain, Hash, URL
- Auto-detect CVE patterns: CVE-YYYY-NNNN
- Save to database with metadata
- Auto-match against assets

### 📅 Complete Date Tracking
- IOC: `valid_from`, `valid_until`, `created_at`
- Malware: `original_creation_date`, `modification_date`
- Vulnerability: `original_creation_date`, `modification_date`
- Relationships: `created_at`, `updated_at`, `start_time`, `stop_time`
- Containers: `created_at`, `updated_at`, `published`

### 🎯 Improved UI Display
- Date columns now properly formatted
- Optional fields gracefully handled
- Upload progress feedback
- Upload history tracking

---

## 📝 Testing Commands

### Test Malware API
```bash
curl http://localhost:8001/api/malwares | jq '.[0]'
```

### Test Vulnerability API
```bash
curl http://localhost:8001/api/vulnerabilities | jq '.[0]'
```

### Test PDF Upload
```bash
curl -X POST -F "file=@report.pdf" http://localhost:8001/api/upload
```

### Test Upload Log
```bash
curl http://localhost:8001/api/upload-log
```

---

## 🔄 Next Steps (Optional)

1. **Performance Optimization**
   - Cache PDF extraction results
   - Batch process multiple uploads
   - Optimize database queries for large datasets

2. **Enhanced PDF Processing**
   - Support table extraction
   - Support structured data in PDF
   - Add OCR for scanned PDFs (requires pytesseract)

3. **Advanced Date Filtering**
   - Add date range filters in UI
   - Add sorting by modification date
   - Add "recently updated" view

---

## 📂 Files Modified

```
✓ frontend/index.html              # Fixed field bindings (2 locations)
✓ agents/ti_fetch_agent.py        # Conditional date field inclusion
✓ main.py                          # PDF extraction + date fields for uploads
```

## 📦 Dependencies Added

```
✓ pdfplumber                       # PDF text extraction
✓ pdfminer.six                     # PDF mining support
✓ pypdfium2                        # PDF processing
✓ cryptography                     # Encryption support
✓ cffi                             # C FFI support
✓ pycparser                        # C parser
```

---

**Status: READY FOR PRODUCTION** ✅


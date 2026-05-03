# 📋 TI Agentic - Cập nhật Trường Dữ Liệu & GraphQL Queries

**Ngày cập nhật:** 30/04/2026  
**Trạng thái:** ✅ HOÀN TẤT 100%

---

## 1️⃣ IOC Scanner - Thêm Trường Valid From/Until

### File: `agents/ti_fetch_agent.py` (dòng 80-94)

**Trường được thêm:**
```python
"valid_from": str(n.get("valid_from",""))[:10],
"valid_until": str(n.get("valid_until",""))[:10],
```

**GraphQL Query cập nhật:**
```graphql
query($first:Int $after:ID){
  indicators(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{
      id name pattern indicator_types confidence description
      valid_from valid_until created_at objectLabel{value}
    }}
  }
}
```

**Giá trị trả về:**
- `valid_from`: Ngày bắt đầu hiệu lực (từ OpenCTI)
- `valid_until`: Ngày kết thúc hiệu lực (từ OpenCTI)

---

## 2️⃣ Malware Tracker - Thêm Original Creation Date & Modification Date

### File: `agents/ti_fetch_agent.py` (dòng 96-113)

**Trường được thêm:**
```python
"original_creation_date": str(n.get("created",""))[:10],
"modification_date": str(n.get("updated",""))[:10],
```

**GraphQL Query cập nhật:**
```graphql
query($first:Int $after:ID){
  malwares(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{
      id name aliases malware_types first_seen last_seen confidence description
      created created_at updated objectLabel{value}
    }}
  }
}
```

**Giá trị trả về:**
- `original_creation_date`: Ngày tạo ban đầu (từ `created`)
- `modification_date`: Ngày sửa đổi gần nhất (từ `updated`)
- `first_seen`: Ngày phát hiện lần đầu
- `last_seen`: Lần cuối cùng phát hiện

---

## 3️⃣ Vulnerability Tracker - Thêm Original Creation Date & Modification Date

### File: `agents/ti_fetch_agent.py` (dòng 115-133)

**Trường được thêm:**
```python
"original_creation_date": str(n.get("created",""))[:10],
"modification_date": str(n.get("updated",""))[:10],
```

**GraphQL Query cập nhật:**
```graphql
query($first:Int $after:ID){
  vulnerabilities(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{
      id name description x_opencti_cvss_base_score
      x_opencti_cvss_base_severity created created_at updated objectLabel{value}
    }}
  }
}
```

**Giá trị trả về:**
- `original_creation_date`: Ngày tạo ban đầu (từ `created`)
- `modification_date`: Ngày sửa đổi gần nhất (từ `updated`)
- `cvss_score`: CVSS Base Score
- `severity`: Mức độ nghiêm trọng

---

## 4️⃣ Relationships Detail - Latest Created Relationships

### File: `main.py` (dòng 197-233)

**Trường được thêm:**
```python
"updated_at": str(n.get("updated", ""))[:16],
"start_time": str(n.get("start_time", ""))[:10],
"stop_time": str(n.get("stop_time", ""))[:10],
```

**GraphQL Query cập nhật:**
```graphql
query($id:String! $first:Int){
  stixCoreRelationships(
    fromOrToId:[$id] first:$first
    orderBy:created_at orderMode:desc
  ){
    edges{ node{
      id relationship_type created_at updated start_time stop_time confidence
      from{ entity_type ... on Indicator { name } ... on Malware { name } ... }
      to{ entity_type ... on Indicator { name } ... on Malware { name } ... }
    }}
  }
}
```

**Giá trị trả về:**
- `created_at`: Thời gian tạo relationship
- `updated_at`: Thời gian cập nhật relationship
- `start_time`: Thời gian bắt đầu hoạt động (nếu có)
- `stop_time`: Thời gian kết thúc hoạt động (nếu có)
- **Sắp xếp:** Latest created relationships (descending by created_at)

---

## 5️⃣ Containers Detail - Latest Containers About The Object

### File: `main.py` (dòng 235-304)

**Trường được thêm:**
```python
"created_at": str(n.get("created") or n.get("created_at", ""))[:10],
"updated_at": str(n.get("updated") or n.get("updated_at", ""))[:10],
"published": str(n.get("published", ""))[:10],
```

**GraphQL Query cập nhật:**
```graphql
query($id:String! $first:Int){
  stixCoreObjectContainers(id:$id first:$first orderBy:created_at orderMode:desc){
    edges{ node{
      id entity_type created_at updated
      ... on Report { 
        id name published created updated confidence
        createdBy { name }
        objectMarking { definition }
      }
      ... on Note { id attribute_abstract created updated }
      ... on Case { id name created updated }
      ... on Grouping { id name created updated }
    }}
  }
}
```

**Alternative Query cho Reports:**
```graphql
query($id:String! $first:Int){
  reports(
    first:$first
    orderBy:published orderMode:desc
    filters:{
      mode:and
      filters:[{key:"objects" values:[$id]}]
      filterGroups:[]
    }
  ){
    edges{ node{
      id name published created updated confidence
      createdBy{ name }
      objectMarking{ definition }
    }}
  }
}
```

**Giá trị trả về:**
- `created_at`: Thời gian tạo container
- `updated_at`: Thời gian cập nhật container
- `published`: Thời gian xuất bản (cho Reports)
- **Sắp xếp:** Latest containers (descending by created_at)

---

## 📊 Kiểm tra & Xác nhận

✅ **Code Updates Verified:**
- IOC Scanner: `valid_from`, `valid_until` ✓
- Malware Tracker: `original_creation_date`, `modification_date` ✓
- Vulnerability Tracker: `original_creation_date`, `modification_date` ✓
- Relationships: `updated_at`, `start_time`, `stop_time` ✓
- Containers: `created_at`, `updated_at`, `published` ✓

✅ **Server Status:**
- Backend: Running on `http://localhost:8001`
- Data Source: OpenCTI (Real data)
- Endpoints: All responsive

✅ **API Endpoints Tested:**
- `/api/iocs` - Returns IOCs with `valid_from` ✓
- `/api/malwares` - Returns malwares ✓
- `/api/vulnerabilities` - Returns vulnerabilities ✓
- `/api/ti/detail` - Returns relationships & containers with new fields ✓

---

## 🔄 Cách Sử Dụng

### Lấy IOC với Valid From/Until:
```bash
curl http://localhost:8001/api/iocs
```

### Lấy Malware với Dates:
```bash
curl http://localhost:8001/api/malwares
```

### Lấy Detail Object với Relationships & Containers:
```bash
curl "http://localhost:8001/api/ti/detail?id=OBJECT_ID&name=NAME&type=TYPE"
```

### Manual Refresh:
```bash
curl -X POST http://localhost:8001/api/refresh
```

---

## 📝 Ghi Chú

- Dữ liệu được tự động refresh mỗi 15 phút
- Các trường null/empty sẽ trả về chuỗi rỗng ""
- Date format: YYYY-MM-DD
- DateTime format: YYYY-MM-DD HH:MM (cho relationships)
- Sắp xếp mặc định: Latest created (descending by created_at)


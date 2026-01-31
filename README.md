# SQL Injection in PHPGurukul Hospital Management System V4.0 (manage-users.php)

> **Disclaimer**: This repository is for educational purposes and security research only. The author is not responsible for any misuse of the information provided. Please use this information responsibly to secure your own systems.

## 1. Vulnerability Overview

- **Product**: Hospital Management System (HMS)
- **Vendor**: PHPGurukul
- **Version**: V4.0 (Latest)
- **Vulnerability Type**: SQL Injection (Time-based Blind)
- **Affected Component**: `/hospital/hms/admin/manage-users.php`
- **Authentication**: Required (Administrator privileges)
- **Method**: GET
- **Parameter**: `id`

## 2. Vulnerability Description

A critical SQL Injection vulnerability exists in the **Hospital Management System V4.0** developed by PHPGurukul. The vulnerability is located in the **Admin Dashboard** under the "Manage Users" module.

Specifically, in the `/hospital/hms/admin/manage-users.php` file, the application accepts the `id` parameter via a GET request to delete a user. The application directly concatenates this parameter into a raw SQL `DELETE` statement without any sanitization or parameterized queries.

An attacker with administrative privileges (or an attacker who has hijacked an admin session) can exploit this vulnerability to:
1.  Inject arbitrary SQL commands.
2.  Execute **Time-based Blind SQL Injection** to extract sensitive data (e.g., database version, user passwords) character by character.
3.  Potentially delete all records in the `users` table by manipulating the `WHERE` clause (e.g., `OR 1=1`), causing a Denial of Service (DoS) and data loss.

## 3. Technical Details & Root Cause

**Vulnerable File**: `hospital/hms/admin/manage-users.php`

**Vulnerable Code Snippet (Line 12):**

    if(isset($_GET['del']))
    {
        $uid=$_GET['id'];
        mysqli_query($con,"delete from users where id ='$uid'");
        $_SESSION['msg']="data deleted !!";
    }

**Analysis**:
The variable `$uid` is directly assigned from `$_GET['id']` and inserted into the SQL query string. There is no usage of `mysqli_real_escape_string` or Prepared Statements.

### Code Analysis Screenshot
<img width="2390" height="1173" alt="fff86e738959bd4fe19342719e84b16b" src="https://github.com/user-attachments/assets/0cb360d8-003b-454b-a0fc-472341e84814" />


## 4. Proof of Concept (PoC)

### Payload
To verify the Time-based Blind SQL Injection, we can inject a `SLEEP(5)` command. If the vulnerability exists, the server response will be delayed by approximately 5 seconds.

**Vector**:

    1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--+

**Full Exploit URL**:

    http://localhost/Hospital-Management-System-PHP/hospital/hms/admin/manage-users.php?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--+&del=delete

### Reproduction Steps
1.  Log in to the application as an **Administrator**.
2.  Navigate to **Users** -> **Manage Users**.
3.  Click the "Delete" (X) icon for any user, or capture the request using a proxy tool (like Burp Suite).
4.  Modify the `id` parameter in the URL with the payload above.
5.  Observe that the server takes 5+ seconds to respond.

### Execution Evidence (5s Delay)
<img width="2542" height="1549" alt="23af7ba6330e2cee82fac8c97a4500ff" src="https://github.com/user-attachments/assets/2a8ec069-11ea-47fa-afa7-7619acda8d58" />


## 5. Remediation

To fix this vulnerability, the developer should use **Prepared Statements** to handle user input safely.

**Patched Code Example:**

    if(isset($_GET['del']))
    {
        $uid = $_GET['id'];
        // Use Prepared Statement
        $stmt = $con->prepare("DELETE FROM users WHERE id = ?");
        $stmt->bind_param("i", $uid); // 'i' assumes id is an integer
        $stmt->execute();
        $stmt->close();
        $_SESSION['msg']="data deleted !!";
    }

## 6. Timeline
- **Discovery Date**: 2026-01-30
- **Status**: Publicly Disclosed

---

# Appendix: CVE Request Helper (For Form Submission)
> **Note**: This section contains the exact text needed to fill out the CVE/CNA request form. You can delete this section after submission if you wish.

### 1. Vulnerability Type
SQL Injection

### 2. Vendor
PHPGurukul

### 3. Product
Hospital Management System (HMS)

### 4. Version
V4.0

### 5. Description (Standard Format)
PHPGurukul Hospital Management System V4.0 is vulnerable to SQL Injection via the `id` parameter in `/hospital/hms/admin/manage-users.php`. An authenticated attacker can execute arbitrary SQL commands to delete data or extract sensitive information by sending a crafted HTTP GET request containing malicious SQL syntax (e.g., time-based blind injection).

### 6. Attack Type
Remote / Context-dependent

### 7. Impact
- Confidentiality Impact: High (Database dump)
- Integrity Impact: High (Data deletion/modification)
- Availability Impact: High (Potential DoS via table deletion)

# 🛡️ SecureShare — Cybersecurity Platform & SIEM Log Analyzer

**SecureShare** is an enterprise-grade **Cybersecurity File Vault, Access Control System, and SIEM (Security Information & Event Management) Threat Analyzer**. It unifies zero-knowledge authenticated encryption at rest with automated sliding-window threat detection to safeguard sensitive data and detect live cyber attacks in real time.

---

## 📑 Table of Contents

1. [Project Overview](#-1-project-overview)
2. [Key Architecture & How It Works](#-2-key-architecture--how-it-works)
3. [Cybersecurity Attacks & Vulnerabilities Detected](#-3-cybersecurity-attacks--vulnerabilities-detected)
4. [Services, Ports & Endpoints](#-4-services-ports--endpoints)
5. [Quick Start & Launch Guide](#-5-quick-start--launch-guide)
6. [Comprehensive Manual Testing Guide](#-6-comprehensive-manual-testing-guide)
   * [Testing Safe / Normal Operations](#a-testing-safe--legitimate-operations)
   * [Testing Unsafe / Malicious Cyber Attacks](#b-testing-unsafe--malicious-cyber-attacks)
   * [Testing File Tampering & Cryptographic Integrity Violations](#c-testing-file-tampering--data-corruption)
7. [Automated Test Suite (62 / 62 Tests)](#-7-automated-test-suite)
8. [Default Credentials Reference](#-8-default-credentials-reference)

---

## 🌐 1. Project Overview

### What is SecureShare?
SecureShare is a full-stack cybersecurity platform designed to solve two core security challenges:
1. **Data Security at Rest & in Transit:** Protecting confidential files using **AES-256-GCM (Galois/Counter Mode)** authenticated encryption and **SHA-256** integrity verification so files cannot be intercepted, read, or modified by unauthorized parties.
2. **Real-Time Threat Detection & SIEM Log Analysis:** Continuously monitoring authentication streams, access logs, and API requests to detect and mitigate malicious activity (Brute-Force attacks, SQL Injections, Credential Stuffing, and Directory Traversal probes).

### What is it used for?
* **Confidential Document Sharing:** Encrypting sensitive financial reports, private keys, legal documents, and source code before storing them on disk.
* **Security Operations Center (SOC) & SIEM Monitoring:** Ingesting access logs and running automated algorithmic detection against malicious traffic patterns.
* **Audit & Forensic Logging:** Maintaining an immutable audit trail of every login, failed attempt, file upload, download, and verification event.
* **Role-Based Access Control (RBAC):** Restricting sensitive administrative endpoints to verified administrators while providing standard access to normal users.

---

## 🏗️ 2. Key Architecture & How It Works

SecureShare is structured into three integrated backend subsystems and a modern React dashboard:

```
                                  ┌─────────────────────────────────────────┐
                                  │      Frontend React 19 + Vite UI        │
                                  │         http://localhost:5173           │
                                  └───────────────┬─────────────────────────┘
                                                  │
                      ┌───────────────────────────┼───────────────────────────┐
                      │ (Port 5000)               │ (Port 8001)               │ (Port 5000 / auth)
                      ▼                           ▼                           ▼
        ┌───────────────────────────┐ ┌───────────────────────────┐ ┌───────────────────────────┐
        │  SIEM Threat Analyzer     │ │  Secure File Sharing API  │ │  Authentication & RBAC    │
        │  (backend/analyzer/)      │ │  (backend/files/)         │ │  (backend/auth/)          │
        │  - Sliding Window Engine  │ │  - AES-256-GCM Encryption │ │  - Bcrypt Password Hash   │
        │  - Attack Signature Match │ │  - SHA-256 Integrity Check│ │  - HS256 JWT Generation    │
        │  - Security REST APIs     │ │  - Encrypted Storage Vault│ │  - Audit Access Logging   │
        └─────────────┬─────────────┘ └─────────────┬─────────────┘ └─────────────┬─────────────┘
                      │                             │                             │
                      │ reads & analyzes            │ writes .enc & metadata      │ appends audit entries
                      ▼                             ▼                             ▼
        ┌───────────────────────────────────────────────────────────────────────────────────────┐
        │  Persistent Storage & Logs: backend/logs/app_access.log & backend/files/storage/      │
        └───────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Cryptographic File Vault (`backend/files/`)
* **Cipher:** AES-256-GCM with a cryptographically secure 256-bit (32-byte) master key and 96-bit (12-byte) unique random nonces per file.
* **Integrity Guarantee:** Before encryption, a 64-character lowercase SHA-256 hash digest is generated. During download or manual verification, constant-time comparison (`hmac.compare_digest`) validates the decrypted bytes.
* **Storage at Rest:** Uploaded files are stored in `backend/files/storage/<file_id>.enc` purely as ciphertext. If an attacker gains direct disk access, they cannot read the files without the key.

### 2. SIEM Threat Detection Engine (`backend/analyzer/`)
* **Log Ingestion:** Parses structured JSON and standard tagged key-value logs from `backend/logs/app_access.log`.
* **Sliding-Window Memory Model:** Tracks event timestamps in chronological order to detect high-frequency attack bursts without database overhead.
* **Automated Mitigation:** Automatically suggests firewall block rules (e.g., `iptables -A INPUT -s <IP> -j DROP`) and security advisories for each incident.

### 3. Authentication & Access Control (`backend/auth/`)
* **Password Security:** Uses bcrypt with a workload factor of 12 rounds and automatic salting.
* **JWT Tokens:** Signs JSON Web Tokens (HS256) containing `sub` (User ID), `email`, `username`, and `role` claims with configurable token expiration.
* **Audit Logger:** Every authentication event is written to `backend/logs/app_access.log`.

---

## 🚨 3. Cybersecurity Attacks & Vulnerabilities Detected

| Attack Vector | SIEM Alert Type | Detection Rule / Algorithm | Severity | Forensic Trigger Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **Brute Force Attack** | `BRUTE_FORCE_ATTACK` | Single IP generates **> 5 failed login attempts within a 60-second sliding window**. | 🔴 `CRITICAL` / `HIGH` | Rapid HTTP 401/403 responses targeting accounts like `admin`. |
| **SQL Injection (SQLi)** | `SQL_INJECTION` | Payload matching SQL syntax patterns in query parameters or auth fields. | 🔴 `CRITICAL` | `' OR '1'='1`, `UNION SELECT`, `xp_cmdshell`, `waitfor delay`, `--`. |
| **Credential Stuffing** | `CREDENTIAL_STUFFING` | Single IP attempts failed logins targeting **> 3 distinct usernames within 120 seconds**. | 🟠 `HIGH` | Bot scanning multiple accounts (`root`, `admin`, `user1`, `finance`). |
| **Path Traversal** | `PATH_TRAVERSAL` | Probing file endpoints with directory breakout sequences. | 🟠 `HIGH` | `../../../../etc/passwd`, `.env`, `.git/config`, `%2e%2e%2f`. |
| **Rate Anomaly / DDoS** | `RATE_ANOMALY` | Request frequency exceeds **> 30 requests within 10 seconds** from one IP. | 🟡 `HIGH` / `MEDIUM` | Automated scraping, flood bots, or unthrottled API probing. |
| **File Tampering** | `INTEGRITY_VIOLATION` | Decrypted file payload fails SHA-256 constant-time hash comparison or GCM tag check. | 🔴 `CRITICAL` | Modified bytes in stored `.enc` files or damaged ciphertext. |

---

## 🔌 4. Services, Ports & Endpoints

| Service | Technology | Port / Base URL | Purpose |
| :--- | :--- | :--- | :--- |
| **Frontend Web App** | React 19 + Vite | [http://localhost:5173](http://localhost:5173) | Interactive Cybersecurity Dashboard, Threat Center, File Vault, SIEM Logs |
| **Log Analyzer & SIEM** | Python HTTP Server | [http://localhost:5000](http://localhost:5000) | Threat detection endpoints, alert query engine, log parsing, attack simulator |
| **Encrypted File Vault** | Python FastAPI + Uvicorn | [http://localhost:8001](http://localhost:8001) | AES-256 file upload, download, verification, Swagger UI at `/docs` |
| **Auth Backend** | Node.js / Express | [http://localhost:5000](http://localhost:5000)/api/auth | User registration, login, JWT token issuance |

---

## 🚀 5. Quick Start & Launch Guide

To run the entire platform, open **3 separate terminal tabs** at the project root (`SecureShare-Cybersecurity`):

### Terminal 1: Frontend Dashboard
```powershell
cd frontend
npm.cmd run dev
```
> Access UI at: **[http://localhost:5173](http://localhost:5173)**

### Terminal 2: Log Analyzer & Threat Engine
```powershell
python backend/analyzer/server.py --port 5000
```
> Threat APIs active at: **[http://localhost:5000](http://localhost:5000)**

### Terminal 3: Secure File Sharing & AES-256 API
```powershell
python backend/files/server.py
```
> Interactive API Docs active at: **[http://localhost:8001/docs](http://localhost:8001/docs)**

---

## 🧪 6. Comprehensive Manual Testing Guide

Follow this guide to manually test and demonstrate both **Safe (legitimate)** and **Unsafe (malicious)** behaviors.

---

### A. Testing SAFE / Legitimate Operations

#### Test 1: User Login & Session Persistence
1. Open your browser to **[http://localhost:5173/login](http://localhost:5173/login)**.
2. Enter the default administrator credentials:
   * **Email/Username:** `admin@secureshare.local` (or `admin`)
   * **Password:** `Admin@123456`
3. Click **Sign In**.
4. **Expected Result:**
   * You are redirected to **[http://localhost:5173/dashboard](http://localhost:5173/dashboard)**.
   * The Navbar displays `👤 admin` and a green `Threat Engine: Active` status indicator.
   * An audit log entry with `status: "SUCCESS"` and `status_code: 200` is recorded in `backend/logs/app_access.log`.

---

#### Test 2: Encrypting and Uploading a File (AES-256-GCM)
1. In the sidebar, click **⬆️ Upload File** ([http://localhost:5173/upload](http://localhost:5173/upload)).
2. Drag & drop any file (e.g. `document.pdf`, `report.txt`, or an image) or click to browse.
3. Type an optional classification (e.g., `Confidential Financial Report 2026`).
4. Click **🔐 Encrypt & Upload**.
5. **Expected Result:**
   * A green confirmation card appears showing:
     * **File Name & File UUID**
     * **Encryption Standard:** `AES-256-GCM`
     * **Original Size vs Encrypted Ciphertext Size**
     * **Computed SHA-256 Hash Digest** (64 hex characters).
   * Check your local file system: Open `backend/files/storage/`. You will see a file named `<UUID>.enc`. If you open it in a text editor, it contains unreadable encrypted binary/ciphertext.

---

#### Test 3: Verifying Cryptographic Integrity (SHA-256 Checksum)
1. In the sidebar, click **📁 My Files** ([http://localhost:5173/files](http://localhost:5173/files)).
2. Find the file you just uploaded in the table.
3. Click the **🛡️ Verify** button next to the file.
4. **Expected Result:**
   * The system computes a fresh SHA-256 hash of the stored file payload in constant time.
   * A green badge labeled **`✓ INTACT`** appears, confirming the file has not suffered bit rot or tampering.

---

#### Test 4: Decrypting & Downloading the Original File
1. On the **My Files** page ([http://localhost:5173/files](http://localhost:5173/files)), click **⬇️ Download**.
2. **Expected Result:**
   * The backend reads the `.enc` ciphertext, extracts the 12-byte nonce, decrypts the payload with AES-256-GCM, validates the SHA-256 digest, and streams the decrypted plaintext back to your browser with original filename and MIME type.
   * Open the downloaded file to confirm it is byte-for-byte identical to what you uploaded.

---

#### Test 5: Generating Shareable Vault Links
1. In the sidebar, click **👥 Shared Files** ([http://localhost:5173/shared](http://localhost:5173/shared)).
2. Click **📋 Copy Link** next to any encrypted file.
3. Paste the URL in a new browser tab.
4. **Expected Result:** The file is securely served and downloaded directly.

---

### B. Testing UNSAFE / Malicious Cyber Attacks

SecureShare provides two methods to test attack detection:

#### Method 1: Using the Interactive Threat Center UI (Easiest)

1. In the sidebar, click **🚨 Threat Center** ([http://localhost:5173/threats](http://localhost:5173/threats)).
2. You will see the **Interactive Cyber Attack Simulator & Payload Injector**.

##### 🔴 1. Test Brute Force Attack:
* Click **`🔴 Simulate Brute Force`**.
* **What happens:** The system injects 8 failed login attempts within 35 seconds from IP `198.51.100.42` targeting user `admin`.
* **Detection:** The Threat Engine flags a **`CRITICAL: BRUTE_FORCE_ATTACK`** incident card with:
  * Attacker IP: `198.51.100.42`
  * Target Account: `admin`
  * Actionable Mitigation: `iptables -A INPUT -s 198.51.100.42 -j DROP` (click **📋 Copy Firewall Rule** to copy the command).

##### 💉 2. Test SQL Injection (SQLi) Probing:
* Click **`💉 Simulate SQL Injection`**.
* **What happens:** Injects SQL injection signatures (`' OR '1'='1`, `UNION SELECT`).
* **Detection:** A **`CRITICAL: SQL_INJECTION`** alert appears with payload evidence and WAF sanitization recommendations.

##### 👥 3. Test Credential Stuffing:
* Click **`👥 Simulate Credential Stuffing`**.
* **What happens:** Injects failed logins across multiple distinct usernames (`root`, `admin`, `ahmed`, `anfas`) from IP `203.0.113.88`.
* **Detection:** A **`HIGH: CREDENTIAL_STUFFING`** alert appears identifying the multi-user targeting pattern.

##### 📂 4. Test Directory / Path Traversal:
* Click **`📂 Simulate Path Traversal`**.
* **What happens:** Injects requests targeting `../../../../etc/passwd` and `.env`.
* **Detection:** A **`HIGH: PATH_TRAVERSAL`** alert appears.

##### ⚡ 5. Test Multi-Vector Attack:
* Click **`⚡ Simulate Full Multi-Vector Attack`** to trigger all vectors simultaneously and view the categorized threat matrix.

---

#### Method 2: Injecting Attacks via Terminal / CLI

You can simulate attacks by running the Python mock generator from your terminal:

```powershell
# Run attack simulation generator
python backend/analyzer/mock_generator.py
```

Then visit **[http://localhost:5173/dashboard](http://localhost:5173/dashboard)** or **[http://localhost:5000/api/alerts](http://localhost:5000/api/alerts)** to inspect the live alerts.

---

### C. Testing File Tampering & Data Corruption

You can demonstrate cryptographic tamper detection and integrity failure:

1. Upload a test file (e.g. `test_secret.txt` containing `Confidential Data`) via **[http://localhost:5173/upload](http://localhost:5173/upload)**.
2. Note the generated `file_id` (e.g. `3a4f8d22-....`).
3. Open the encrypted file on disk in your code editor: `backend/files/storage/<file_id>.enc`.
4. Modify a few random characters in the `.enc` file (simulating an unauthorized attacker modifying bytes on disk) and save the file.
5. Go to **My Files** ([http://localhost:5173/files](http://localhost:5173/files)) and click **🛡️ Verify** next to that file.
6. **Expected Result:**
   * The system detects that the cryptographic checksum or GCM authentication tag fails.
   * The UI displays a red **`✗ TAMPERED`** alert badge.
   * Attempting to download the file triggers a secure `DecryptionError` / `IntegrityVerificationError` (HTTP 500/400) preventing corrupted or malicious payload execution.

---

## 🧪 7. Automated Test Suite

SecureShare includes a 62-test automated unit and integration test suite across all modules.

To run the complete test suite:

```powershell
# Run with Pytest
python -m pytest backend/
```

*Or using Python's standard library test discovery:*
```powershell
python -m unittest discover -s backend -p "test_*.py"
```

### Test Suite Coverage Summary:
* **Log Analyzer (`backend/analyzer/test_analyzer.py`):** 20 tests verifying KV/JSON parsing, sliding-window Brute Force (>5 in 60s), Credential Stuffing (>3 in 120s), SQLi, XSS, Path Traversal regex matching, and REST endpoints.
* **Authentication & RBAC (`backend/auth/test_auth.py`):** 32 tests verifying user registration, bcrypt hashing, JWT issuance & expiry, role enforcement (`require_admin`, `require_user`), access audit logging, and SIEM interoperability.
* **File Encryption & Storage (`backend/files/test_files.py`):** 10 tests verifying AES-256-GCM encryption/decryption round-trips, SHA-256 constant-time verification, corrupted ciphertext detection (`DecryptionError`), hash tampering detection (`IntegrityVerificationError`), and FastAPI endpoints.

---

## 🔑 8. Default Credentials Reference

| Role | Username / Identifier | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` / `admin@secureshare.local` | `Admin@123456` | Full administrative access, user management, threat feeds |
| **Standard User** | `user` / `user@secureshare.local` | `User@123456` | Encrypted file upload, download, personal vault management |

---

## 🏛️ Summary of Key Security Standards

* **Encryption at Rest:** AES-256-GCM (Authenticated Encryption with Associated Data)
* **Cryptographic Digests:** SHA-256 with constant-time verification (`hmac.compare_digest`)
* **Password Security:** Bcrypt with cost factor 12
* **Token Authentication:** JSON Web Tokens (JWT) signed with HS256
* **SIEM Engine:** Multi-threaded sliding-window correlation algorithm

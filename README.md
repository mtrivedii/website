# Secure Azure Web Application – `maanitwebapp.com`

This project is a secure, full-stack web application deployed on Microsoft Azure. It implements layered security controls aligned with professional standards such as CIS Controls, NIST SP 800-53, and OWASP best practices. The system was developed as part of the *Advanced Cyber Security* course at Fontys University of Applied Sciences.

## 🌐 Overview

- **Project Type:** Secure cloud-hosted web application (no longer live)
- **Stack:** Azure App Service (Linux) + Azure SQL + Node.js + GitHub Actions CI/CD
- **Security Highlights:** MFA, 2FA (TOTP), RBAC, HTTPS, encrypted DB, secure file upload, monitoring

---

## 📦 Features

### ✅ Authentication & Access Control
- Multi-Factor Authentication using TOTP (Google/Microsoft Authenticator)
- JWT-based session management (stored in secure `httpOnly` cookies)
- Role-Based Access Control (admin/user roles)
- Secure registration with NIST-compliant password policy and rate limiting

### 🔐 Security Architecture
- Azure Front Door with custom WAF rules (SQLi, XSS, SSRF, Command Injection)
- Encrypted communication via HTTPS and TLS (port 443 and 1433)
- Azure SQL with Transparent Data Encryption (TDE) and Entra ID-based access
- App secrets managed via secure environment variables

### ☁️ Cloud-Native Hardening
- Blob Storage uploads via time-limited SAS tokens
- File type, MIME type, and filename validation with blacklisting
- Real-time monitoring with Azure Monitor, App Insights, and Log Analytics
- Defender for Cloud: compliance, vulnerability scanning, auto-remediation

### 📊 CI/CD & DevSecOps
- GitHub Actions pipeline with CodeQL static analysis
- OWASP ZAP used for post-deployment dynamic testing (DAST)
- Compliance mapping against CIS and NIST benchmarks
- Cost-optimized design under Azure for Students budget

---

## 📘 Documentation

All technical documentation (Body of Knowledge, PDR, research article, architecture diagrams) is located in the `/Documentation` folder of this repository.

---

## 📞 Contact

**Maanit Trivedi**  
📧 `maanit49@gmail.com`
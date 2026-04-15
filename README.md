# Project: Sentinel-Patch

### 🛡️ Autonomous Vulnerability Reachability & Remediation Engine
**Status:** Operational | **Target Environment:** Production Microservices

## 📋 Executive Overview
Sentinel-Patch is an intelligent DevSecOps middleware designed to bridge the gap between **Static Analysis** and **Runtime Reality**. Modern container scans typically produce thousands of vulnerabilities, leading to "Alert Fatigue." This project implements a **Reachability Engine** that filters noise and autonomously remediates exploitable paths.

## 🏗️ Project Architecture
The repository simulates a "Client API Gateway" with a standard enterprise structure:
<!-- - `src/`: Core Microservice logic (Node.js/Express). -->
- `infra/`: Infrastructure-as-Code (Terraform & Kubernetes manifests).
- `security/`: Custom automation engines for vulnerability triaging.

## 🚀 The Solution: Reachability Analysis
Standard tools flagged **1,811 CVEs** in this project's legacy base image. 
Sentinel-Patch reduced this to **4 actionable threats** by:
1. **Binary AST Mapping:** Checking if vulnerable libraries are actually referenced by the application code.
2. **Autonomous Remediation:** Automatically generating a Pull Request to migrate to a hardened `alpine` base image.
3. **VEX Reporting:** Generating professional HTML Audit reports comparing the Legacy vs. Hardened state.

## 🛠️ Tech Stack
- **Engine:** Python 3.x
- **Scanner:** Aqua Security Trivy
- **Orchestration:** GitHub Actions
- **Infrastructure:** Docker, Kubernetes, Terraform

## 📈 Impact
- **Noise Reduction:** 99.78%
- **MTTR (Mean Time to Remediation):** < 1 Minute
- **Compliance:** Automated VEX-compliant audit trail generation.
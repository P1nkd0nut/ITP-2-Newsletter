# GroundedCVE Demo Guide & Presentation Script
> **ICT 2114 Integrative Team Project — SIT Team 4**  
> **Presenter**: Tan De Ye  
> **Role**: Lead DevOps & Performance Validation Engineer  

---

## 🎯 Executive Talking Points (What to Say at the Start)

> *"Good morning professors and team. As the Lead DevOps and Performance Validation Engineer for GroundedCVE, my focus is ensuring that our automated threat intelligence pipeline is mathematically sound, factually grounded, and empirically validated against real-world Web and Mobile penetration testing workflows.*
> 
> *Today, I am presenting our **Task 1.2 Scope Pre-Filter**, our **Task 2.4 AI Practical Severity Scoring Engine**, and the **Task 4.1 Ground-Truth Benchmark Validation Suite** that I constructed to empirically measure our Fact Extraction Precision, Hallucination Rate, and CVSS Anomaly Gates."*

---

## 📋 Step-by-Step Live Demo Execution

### Part 1: Run the Task 4.1 Ground-Truth Benchmark
Open PowerShell in the project directory and run:

```powershell
python Backend/run_benchmark.py
```

#### 🗣️ What to Say During the Run:
1. **The Ground-Truth Dataset (Task 4.1)**:
   > *"To avoid generative memorization and prove pipeline precision, I constructed a ground-truth extraction dataset of 20 historical Web and Mobile vulnerability disclosures ([`Backend/data/ground_truth_20.json`](Backend/data/ground_truth_20.json)) — 10 Web (e.g., Citrix Bleed, MOVEit SQLi, Confluence Auth Bypass) and 10 Mobile (e.g., Android PackageInstaller Run-As, Apple BLASTPASS, WebKit escapes)."*

2. **The Key Benchmark Metrics**:
   > *"As you can see from our summary report:*
   > - ***Fact Extraction Precision (FEP %): 100.0%*** *(against our proposal benchmark target of $\ge 95.0\%$). Every extracted CVE ID, version constraint, and URL is verified verbatim against raw source text.*
   > - ***Hallucination Rate (HR %): 0.0%*** *(against our target of $\le 5.0\%$). Zero fabricated fields reach the candidate pool.*
   > - ***Pentest Scope Pre-Filter Accuracy: 100.0%***. *Web and Mobile threats are strictly isolated before scoring occurs.*
   > - ***Average Latency: ~2.9s per disclosure*** *with full LLM evaluation."*

---

### Part 2: Demonstrate the 100-Point AI Scoring & CVSS Anomaly Gate
Point out the leaderboard table printed by `run_benchmark.py`:

#### 🗣️ What to Say:
1. **Why We Replaced Direct CVSS Scoring**:
   > *"In our initial design, CVSS base score had heavy weight. However, as noted in our project review, CVSS is frequently inflated for Day-0 theoretical bugs (defaulted to 10.0 worst-case) or underestimated for complex chains. We replaced direct CVSS weighting with **AI Practical Severity Assessment** (0–10 scale evaluated via Qwen 2.5 72B / Ollama)."*

2. **The 100-Point Formula**:
   > *"Our weekly prioritization score is calculated as:*
   > - ***40 Points***: *CISA KEV catalog (actively weaponized today).*
   > - ***40 Points***: *AI Practical Severity (evaluating RCE, Auth Bypass vs DoS).*
   > - ***20 Points***: *Public GitHub PoC availability (actionable exploit scripts).*
   > - ***Total = 100 Points***."*

3. **The CVSS Discrepancy Gate ($|\Delta| \ge 4.0$)**:
   > *"Look at `CVE-2026-94138` on the screen. The vendor CVSS was scored at **2.0**, but our AI evaluator identified remote command injection primitives in `/send_order.cgi`, giving it **7.0/10.0**. Because the delta $|\Delta| = 5.0 \ge 4.0$, our discrepancy gate immediately flagged it with an **`[!] ANOMALY`** alert for triage investigation."*

---

### Part 3: Show Live Feed Triage & Scraping
Run the live pipeline triage runner:

```powershell
python Backend/run_triage.py
```

#### 🗣️ What to Say:
> *"Here is the live triage pipeline operating on real threat intelligence feeds collected by our scrapers (CISA KEV, NVD 2.0, PortSwigger, Project Zero, GitHub Advisories, and Frida). Items outside Web and Mobile pentesting scope (such as printer spoolers and industrial SCADA) receive 0 points and bypass the queue, while verified Web and Mobile exploits enter the top ranks."*

---

### Part 4: Open the Visual Cyber Dashboard
Launch the interactive web dashboard:

```powershell
python Frontend/run_dashboard.py
```
*(Or open [`Frontend/index.html`](Frontend/index.html) in Chrome/Edge).*

#### 🗣️ What to Say & Click:
1. Show the KPI summary cards (**Total Disclosures**, **CISA KEV Actives**, **Web Stream**, **Mobile Stream**).
2. Filter by source tabs: click **CISA KEV**, then **PortSwigger**, then **Frida / Mobile**.
3. Click **"Inspect Envelope"** on any card to show the modal:
   > *"Notice that for every single item, we compute a cryptographic SHA-256 `Content_Hash`, and we preserve `Raw_Content` 100% unmodified without stripping, so that Yue Heng's downstream verification gate can perform strict regex auditing without data loss."*

---

### Part 5: Prove Quality with the Full Automated Test Suite
To conclude the presentation, run the complete automated test suite:

```powershell
python -m unittest discover -s Testing -p "test_*.py" -v
```

#### 🗣️ What to Say:
> *"Every component is backed by automated testing. Across `test_ingestion.py`, `test_triage.py`, and `test_benchmark.py`, all **25 tests pass with a 100% success rate**."*

---

## ⚡ Quick Cheat Sheet (Commands Summary)

| Step | Command | Purpose |
| :--- | :--- | :--- |
| **1. Benchmark** | `python Backend/run_benchmark.py` | Shows 20-sample validation dataset, FEP 100%, HR 0%, CVSS anomaly detection |
| **2. Triage** | `python Backend/run_triage.py` | Shows live 100-point ranking on live scraped threat feeds |
| **3. Ingest Live** | `python Backend/run_ingestion.py --limit 3` | Fetches live data from all 8 threat feeds |
| **4. Web UI** | `python Frontend/run_dashboard.py` | Launches local browser dashboard (`http://localhost:8080`) |
| **5. Tests** | `python -m unittest discover -s Testing -p "test_*.py" -v` | Runs all 25 unit and integration tests |

---

## 💡 Potential Questions & Ready Answers

**Q: Why don't you clean or chunk the text during ingestion?**  
*A: Cleaning and chunking belong to Phase 3 (assigned to Gavin). Our DevOps and Ingestion requirement (Task 1.3) specifically mandates preserving `Raw_Content` completely unmodified with a SHA-256 hash so that the downstream verification gate can audit claims against ground-truth source text without data loss.*

**Q: Where does the AI evaluation run?**  
*A: We configured a dual-tier gateway. If an `OPENROUTER_API_KEY` is provided in `.env`, it queries `qwen/qwen-2.5-72b-instruct`. If offline or without a key, it falls back seamlessly to our local Ollama container (`qwen2.5:3b`) or our offensive heuristic rules.*

**Q: What is the purpose of the 20-item benchmark dataset?**  
*A: It serves as our static ground-truth testbed for Task 4.1. By benchmarking against known historical disclosures with human-verified facts, we mathematically prove our Fact Extraction Precision (100%) and verify that our CVSS discrepancy gate flags real-world rating anomalies.*

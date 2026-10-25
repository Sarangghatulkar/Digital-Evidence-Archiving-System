# Digital Evidence Archiving System

A forensic-grade desktop application for digital evidence intake, cryptographic archiving, chain-of-custody tracking, integrity verification, and audit reporting.

Built entirely using Python's Standard Library (`tkinter`, `hashlib`, `json`, `csv`, `shutil`, `os`, `datetime`).

---

## 🌟 Key Features

1. **Evidence Intake & Ingestion**:
   - Select any digital evidence file via file dialog.
   - Enter Case ID, Evidence Description, and Collector / Custodian Name.
   - Auto-generates unique standardized forensic Evidence IDs (e.g. `EVD-20261025-XXXXXX`) with manual regenerate option.

2. **1 MB Chunked Cryptographic Hashing (SHA-256)**:
   - Reads files in 1 MB (`1024 * 1024` bytes) buffers for memory efficiency, even on large disk images.
   - Automatically stores evidence metadata and intake hash inside `archive_manifest.json`.

3. **Master & Working Copy Archive Architecture**:
   - Organizes evidence under `archive/<case_id>/`.
   - **Master Copy**: Copied to `archive/<case_id>/master/` and locked as **Read-Only** (`stat.S_IREAD`) to prevent accidental or unauthorized modifications.
   - **Working Copy**: Stored in `archive/<case_id>/working/` for forensic analysis.

4. **Forensic Chain of Custody Audit Log**:
   - Logs every single action (`ADDED`, `VIEWED`, `COPIED`, `VERIFIED`, `EXPORTED`, `TAMPERED`) into `custody_log.csv`.
   - Records UTC/local ISO timestamp, Evidence ID, Case ID, Action, Examiner Name, Reason/Authorization, and Technical details.
   - Built-in **Chain of Custody Viewer** modal with real-time filtering and manual custody event recording.

5. **Cryptographic Integrity Verification**:
   - Re-hashes all archived master files in 1 MB chunks and compares the hash with the intake manifest hash.
   - Displays real-time status in the table: **MATCH** in vibrant green (`#3fb950`) or **TAMPERED** in red (`#f85149`).
   - Double-click any row to open the **Forensic Evidence Inspector** modal with full metadata and SHA-256 hash copying.

6. **Executive Dashboard Cards**:
   - **Total Evidence**: Total number of ingested items.
   - **Archived**: Count of preserved items.
   - **Verified OK**: Items matching their original cryptographic intake hash.
   - **Tampered**: Items with detected byte alteration or missing files.

7. **Audit Report Export**:
   - **`archive_report.json`**: Structured report containing system summary metrics, item details, hashes, and embedded custody history.
   - **`archive_report.csv`**: Tabular CSV report for spreadsheet presentation and legal evidence packages.
   - Automatically logs an `EXPORTED` event to the chain of custody.

8. **User Experience & Extra Tools**:
   - Modern GitHub/VSCode dark theme (`#0d1117`, `#161b22`, `#21262d`).
   - Live system clock and active forensic session identifier.
   - Search bar across Evidence ID, Case ID, File Name, and Collector.
   - Filter dropdown by status (`All`, `MATCH`, `TAMPERED`, `PENDING`).
   - Status bar displaying live updates and storage file statuses.
   - **Tamper Simulation Tool**: Injects an altered byte into a test master copy to demonstrate how the integrity engine flags tampering in red and increments the Tampered dashboard card.

---

## 🚀 How to Run

Ensure Python 3.8+ is installed, then launch `main.py`:

```bash
python main.py
```

No external `pip` dependencies are required.

---

## 📂 File Structure

```text
CFI TAE 1/
├── main.py                  # Complete self-contained application
├── README.md                # Documentation & User Guide
├── archive/                 # Root archive directory
│   └── <case_id>/
│       ├── master/          # Read-only protected master copies
│       └── working/         # Working copies for examiners
├── archive_manifest.json    # JSON manifest of all evidence & intake hashes
├── custody_log.csv          # Chain of custody audit trail
├── archive_report.json      # Generated forensic report (JSON)
└── archive_report.csv       # Generated forensic report (CSV)
```

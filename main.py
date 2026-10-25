"""
Digital Evidence Archiving System
==================================
A forensic-grade desktop application for digital evidence intake, archiving, 
cryptographic hashing (SHA-256), chain of custody tracking, integrity verification,
and reporting.

Built using only Python standard library modules:
- tkinter, ttk: Modern dark-themed graphical user interface
- hashlib: Cryptographic hash calculation (SHA-256 in 1 MB chunks)
- json: Archive manifest storage and structured reporting
- csv: Chain of custody logging and CSV reporting
- shutil, os, stat: File handling and setting read-only archive attributes
- datetime, uuid: Timestamps and unique forensic evidence identifiers
"""

import os
import sys
import stat
import json
import csv
import shutil
import hashlib
import datetime
import uuid
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

APP_TITLE = "Digital Evidence Archiving System"
APP_VERSION = "v1.0 - Forensic Archive Suite"
CHUNK_SIZE = 1024 * 1024  # 1 MB buffer for memory-efficient hashing

# Base directories and filenames
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVE_ROOT = os.path.join(BASE_DIR, "archive")
MANIFEST_FILE = os.path.join(BASE_DIR, "archive_manifest.json")
CUSTODY_LOG_FILE = os.path.join(BASE_DIR, "custody_log.csv")
REPORT_JSON_FILE = os.path.join(BASE_DIR, "archive_report.json")
REPORT_CSV_FILE = os.path.join(BASE_DIR, "archive_report.csv")

# Modern Dark Theme Color Palette
COLOR_BG_APP = "#0d1117"       # Deep dark background
COLOR_BG_SIDEBAR = "#161b22"   # Sidebar background
COLOR_BG_CARD = "#21262d"      # Dashboard card surface
COLOR_BG_HEADER = "#161b22"    # Header background
COLOR_BG_INPUT = "#0d1117"     # Entry fields background
COLOR_BORDER = "#30363d"       # Subtle divider border
COLOR_BORDER_FOCUS = "#58a6ff" # Accent border focus

COLOR_FG_MAIN = "#f0f6fc"      # High contrast text
COLOR_FG_MUTED = "#8b949e"     # Secondary muted text
COLOR_FG_ACCENT = "#58a6ff"    # Primary blue accent

COLOR_BTN_PRIMARY = "#238636"  # GitHub green for positive action
COLOR_BTN_PRIMARY_HOVER = "#2ea043"
COLOR_BTN_DEFAULT = "#21262d"  # Neutral dark button
COLOR_BTN_DEFAULT_HOVER = "#30363d"
COLOR_BTN_DANGER = "#da3633"   # Red warning/tamper action
COLOR_BTN_DANGER_HOVER = "#f85149"

COLOR_STATUS_MATCH = "#3fb950"    # Forensic verification OK (Green)
COLOR_STATUS_TAMPERED = "#f85149" # Forensic tampering detected (Red)
COLOR_STATUS_PENDING = "#d29922"  # Pending verification (Yellow/Amber)

# Ensure archive root directory exists
os.makedirs(ARCHIVE_ROOT, exist_ok=True)


# ==============================================================================
# FORENSIC HASHING & UTILITY FUNCTIONS
# ==============================================================================

def calculate_sha256(filepath, chunk_size=CHUNK_SIZE):
    """
    Calculate the SHA-256 hash of a file by reading it in 1 MB chunks.
    This guarantees constant memory usage regardless of file size.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def format_file_size(size_bytes):
    """Format raw bytes into human-readable size strings (KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_current_timestamp():
    """Return an ISO-standard formatted timestamp string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def generate_evidence_id():
    """Auto-generate a standardized forensic Evidence ID."""
    date_part = datetime.datetime.now().strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"EVD-{date_part}-{unique_suffix}"


def sanitize_filename(filename):
    """Sanitize filename to prevent directory traversal or unsafe path chars."""
    basename = os.path.basename(filename)
    safe_chars = "".join(c for c in basename if c.isalnum() or c in "._- ")
    return safe_chars or "evidence_file"


# ==============================================================================
# ARCHIVE MANIFEST & CUSTODY LOG MANAGEMENT
# ==============================================================================

def load_manifest():
    """Load the evidence manifest from archive_manifest.json."""
    if not os.path.exists(MANIFEST_FILE):
        return {"version": "1.0", "system": APP_TITLE, "evidence": []}
    try:
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "evidence" not in data:
                data["evidence"] = []
            return data
    except Exception as e:
        print(f"Error loading manifest: {e}")
        return {"version": "1.0", "system": APP_TITLE, "evidence": []}


def save_manifest(manifest_data):
    """Save the evidence manifest atomically to archive_manifest.json."""
    manifest_data["last_updated"] = get_current_timestamp()
    temp_file = MANIFEST_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=4)
    # Atomic replace
    if os.path.exists(MANIFEST_FILE):
        os.remove(MANIFEST_FILE)
    os.rename(temp_file, MANIFEST_FILE)


def log_custody_action(evidence_id, case_id, action, user_name, reason, details=""):
    """
    Append an entry to custody_log.csv documenting every action taken
    on any piece of digital evidence.
    """
    fieldnames = ["Timestamp", "Evidence ID", "Case ID", "Action", "User Name", "Reason", "Details"]
    file_exists = os.path.exists(CUSTODY_LOG_FILE)

    entry = {
        "Timestamp": get_current_timestamp(),
        "Evidence ID": evidence_id,
        "Case ID": case_id,
        "Action": action.upper(),
        "User Name": user_name or "Unknown User",
        "Reason": reason or "Standard Operation",
        "Details": details
    }

    try:
        with open(CUSTODY_LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(entry)
    except Exception as e:
        print(f"Error writing to custody log: {e}")


def read_custody_logs(filter_evidence_id=None):
    """Read all custody log entries, optionally filtering by Evidence ID."""
    if not os.path.exists(CUSTODY_LOG_FILE):
        return []
    entries = []
    try:
        with open(CUSTODY_LOG_FILE, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if filter_evidence_id:
                    if row.get("Evidence ID") == filter_evidence_id:
                        entries.append(row)
                else:
                    entries.append(row)
    except Exception as e:
        print(f"Error reading custody log: {e}")
    return entries


def set_file_readonly(path):
    """Set file attributes to strictly Read-Only for master forensic preservation."""
    try:
        # Cross-platform read-only mode (remove write permissions)
        mode = os.stat(path).st_mode
        # Clear write flags for user, group, and others
        os.chmod(path, mode & ~stat.S_IWRITE & ~stat.S_IWGRP & ~stat.S_IWOTH)
    except Exception as e:
        print(f"Warning: could not set read-only on {path}: {e}")


def set_file_writable(path):
    """Temporarily restore write permissions if file needs administrative alteration."""
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IWRITE)
    except Exception as e:
        print(f"Warning: could not set writable on {path}: {e}")


# ==============================================================================
# CUSTOM UI WIDGETS (DARK THEME STYLING)
# ==============================================================================

class StatCard(tk.Frame):
    """A modern metric dashboard card showing title, value, and status color strip."""
    def __init__(self, parent, title, initial_val="0", accent_color=COLOR_FG_ACCENT, icon="📊"):
        super().__init__(parent, bg=COLOR_BG_CARD, highlightthickness=1, highlightbackground=COLOR_BORDER)
        self.accent_color = accent_color
        
        # Top color accent strip
        self.strip = tk.Frame(self, bg=accent_color, height=4)
        self.strip.pack(side="top", fill="x")

        # Container for card content
        self.content_frame = tk.Frame(self, bg=COLOR_BG_CARD, padx=16, pady=12)
        self.content_frame.pack(fill="both", expand=True)

        # Header row: Icon + Title
        top_row = tk.Frame(self.content_frame, bg=COLOR_BG_CARD)
        top_row.pack(fill="x", anchor="w")

        self.lbl_icon = tk.Label(top_row, text=icon, font=("Segoe UI Emoji", 14), bg=COLOR_BG_CARD, fg=accent_color)
        self.lbl_icon.pack(side="left", padx=(0, 6))

        self.lbl_title = tk.Label(top_row, text=title.upper(), font=("Segoe UI", 9, "bold"), bg=COLOR_BG_CARD, fg=COLOR_FG_MUTED)
        self.lbl_title.pack(side="left")

        # Big metric number
        self.lbl_val = tk.Label(self.content_frame, text=initial_val, font=("Segoe UI", 24, "bold"), bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN)
        self.lbl_val.pack(anchor="w", pady=(6, 0))

    def update_value(self, new_val):
        self.lbl_val.config(text=str(new_val))


class ModernButton(tk.Button):
    """Flat styled button with hover transition animations."""
    def __init__(self, parent, text, command=None, bg_color=COLOR_BTN_DEFAULT,
                 hover_color=COLOR_BTN_DEFAULT_HOVER, fg_color=COLOR_FG_MAIN,
                 font=("Segoe UI", 10, "bold"), icon="", **kwargs):
        display_text = f"{icon}  {text}" if icon else text
        super().__init__(parent, text=display_text, command=command, bg=bg_color,
                         fg=fg_color, activebackground=hover_color, activeforeground=fg_color,
                         relief="flat", bd=0, padx=14, pady=8, font=font, cursor="hand2", **kwargs)
        self.default_bg = bg_color
        self.hover_bg = hover_color
        self.bind("<Enter>", lambda e: self.config(bg=self.hover_bg))
        self.bind("<Leave>", lambda e: self.config(bg=self.default_bg))


# ==============================================================================
# MODAL DIALOGS
# ==============================================================================

class AddEvidenceDialog(tk.Toplevel):
    """Modal dialog for ingesting new digital evidence."""
    def __init__(self, parent, on_success_callback):
        super().__init__(parent)
        self.title("Intake New Digital Evidence")
        self.geometry("640x600")
        self.resizable(False, False)
        self.configure(bg=COLOR_BG_APP)
        self.transient(parent)
        self.grab_set()

        self.on_success = on_success_callback
        self.selected_filepath = ""

        # Center dialog
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 320
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 300
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

        self._build_ui()

    def _build_ui(self):
        # Header banner
        header = tk.Frame(self, bg=COLOR_BG_HEADER, padx=20, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="📥 Digital Evidence Intake", font=("Segoe UI", 14, "bold"),
                 bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN).pack(anchor="w")
        tk.Label(header, text="Select evidence file, calculate SHA-256 intake hash, and secure master copy",
                 font=("Segoe UI", 9), bg=COLOR_BG_HEADER, fg=COLOR_FG_MUTED).pack(anchor="w", pady=(2, 0))

        # Main Form Container
        form = tk.Frame(self, bg=COLOR_BG_APP, padx=24, pady=16)
        form.pack(fill="both", expand=True)

        # File Selection Row
        lbl_file = tk.Label(form, text="Evidence Source File *", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN)
        lbl_file.pack(anchor="w", pady=(4, 2))

        file_row = tk.Frame(form, bg=COLOR_BG_APP)
        file_row.pack(fill="x", pady=(0, 10))

        self.ent_filepath = tk.Entry(file_row, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                     insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_filepath.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        btn_browse = ModernButton(file_row, text="Browse...", command=self._browse_file,
                                  bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📁")
        btn_browse.pack(side="right")

        self.lbl_file_info = tk.Label(form, text="No file selected (size: 0 B)", font=("Segoe UI", 8),
                                      bg=COLOR_BG_APP, fg=COLOR_FG_MUTED)
        self.lbl_file_info.pack(anchor="w", pady=(0, 10))

        # Evidence ID (Auto-generated with refresh option)
        lbl_evd_id = tk.Label(form, text="Evidence ID (Auto-generated) *", font=("Segoe UI", 9, "bold"),
                              bg=COLOR_BG_APP, fg=COLOR_FG_MAIN)
        lbl_evd_id.pack(anchor="w", pady=(2, 2))

        id_row = tk.Frame(form, bg=COLOR_BG_APP)
        id_row.pack(fill="x", pady=(0, 10))

        self.ent_id = tk.Entry(id_row, bg=COLOR_BG_CARD, fg=COLOR_FG_ACCENT,
                               insertbackground=COLOR_FG_MAIN, relief="flat", font=("Consolas", 11, "bold"))
        self.ent_id.insert(0, generate_evidence_id())
        self.ent_id.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        btn_new_id = ModernButton(id_row, text="Regen ID", command=self._regen_id,
                                  bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="🔄")
        btn_new_id.pack(side="right")

        # Case ID
        lbl_case = tk.Label(form, text="Case ID (e.g., CASE-2026-001) *", font=("Segoe UI", 9, "bold"),
                            bg=COLOR_BG_APP, fg=COLOR_FG_MAIN)
        lbl_case.pack(anchor="w", pady=(2, 2))
        self.ent_case = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                 insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_case.insert(0, "CASE-" + datetime.datetime.now().strftime("%Y-%m"))
        self.ent_case.pack(fill="x", ipady=6, pady=(0, 10))

        # Collector / Examiner Name
        lbl_collector = tk.Label(form, text="Collector / Evidence Custodian Name *", font=("Segoe UI", 9, "bold"),
                                 bg=COLOR_BG_APP, fg=COLOR_FG_MAIN)
        lbl_collector.pack(anchor="w", pady=(2, 2))
        self.ent_collector = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                      insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_collector.insert(0, os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator")))
        self.ent_collector.pack(fill="x", ipady=6, pady=(0, 10))

        # Description / Chain Notes
        lbl_desc = tk.Label(form, text="Evidence Description & Source Details *", font=("Segoe UI", 9, "bold"),
                            bg=COLOR_BG_APP, fg=COLOR_FG_MAIN)
        lbl_desc.pack(anchor="w", pady=(2, 2))
        self.txt_desc = tk.Text(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, insertbackground=COLOR_FG_MAIN,
                                relief="flat", font=("Segoe UI", 9), height=3)
        self.txt_desc.pack(fill="x", pady=(0, 15))

        # Action Buttons Row
        btn_row = tk.Frame(self, bg=COLOR_BG_APP, padx=24, pady=12)
        btn_row.pack(side="bottom", fill="x")

        btn_cancel = ModernButton(btn_row, text="Cancel", command=self.destroy,
                                  bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER)
        btn_cancel.pack(side="right", padx=(8, 0))

        self.btn_submit = ModernButton(btn_row, text="Archive & Compute Hash", command=self._submit,
                                       bg_color=COLOR_BTN_PRIMARY, hover_color=COLOR_BTN_PRIMARY_HOVER, icon="🔒")
        self.btn_submit.pack(side="right")

    def _browse_file(self):
        filename = filedialog.askopenfilename(
            parent=self,
            title="Select Digital Evidence File"
        )
        if filename:
            self.selected_filepath = filename
            self.ent_filepath.delete(0, tk.END)
            self.ent_filepath.insert(0, filename)
            try:
                size = os.path.getsize(filename)
                self.lbl_file_info.config(
                    text=f"File: {os.path.basename(filename)} | Size: {format_file_size(size)} ({size:,} bytes)",
                    fg=COLOR_FG_ACCENT
                )
            except Exception as e:
                self.lbl_file_info.config(text=f"Error reading file info: {e}", fg=COLOR_STATUS_TAMPERED)

    def _regen_id(self):
        self.ent_id.delete(0, tk.END)
        self.ent_id.insert(0, generate_evidence_id())

    def _submit(self):
        filepath = self.ent_filepath.get().strip()
        evd_id = self.ent_id.get().strip()
        case_id = self.ent_case.get().strip()
        collector = self.ent_collector.get().strip()
        desc = self.txt_desc.get("1.0", tk.END).strip()

        # Validation
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid, existing evidence file.", parent=self)
            return
        if not evd_id:
            messagebox.showerror("Error", "Evidence ID cannot be empty.", parent=self)
            return
        if not case_id:
            messagebox.showerror("Error", "Case ID cannot be empty.", parent=self)
            return
        if not collector:
            messagebox.showerror("Error", "Collector Name cannot be empty.", parent=self)
            return
        if not desc:
            messagebox.showerror("Error", "Please provide a brief description for chain of custody.", parent=self)
            return

        # Disable submit button to indicate processing
        self.btn_submit.config(state="disabled", text="Archiving & Hashing...")
        self.update_idletasks()

        try:
            # Step 1: Calculate intake SHA-256 hash in 1 MB chunks
            intake_hash = calculate_sha256(filepath, chunk_size=CHUNK_SIZE)
            file_size = os.path.getsize(filepath)
            original_name = os.path.basename(filepath)
            safe_name = sanitize_filename(original_name)

            # Step 2: Establish directory structure /archive/<case_id>/
            safe_case = sanitize_filename(case_id).replace(" ", "_")
            case_folder = os.path.join(ARCHIVE_ROOT, safe_case)
            master_dir = os.path.join(case_folder, "master")
            working_dir = os.path.join(case_folder, "working")
            os.makedirs(master_dir, exist_ok=True)
            os.makedirs(working_dir, exist_ok=True)

            # File naming in archive
            archive_filename = f"{evd_id}_{safe_name}"
            master_filepath = os.path.join(master_dir, archive_filename)
            working_filepath = os.path.join(working_dir, archive_filename)

            # Step 3: Copy Master and Working copies
            shutil.copy2(filepath, master_filepath)
            shutil.copy2(filepath, working_filepath)

            # Set Master copy to strictly READ-ONLY
            set_file_readonly(master_filepath)

            # Step 4: Record in manifest
            manifest = load_manifest()
            
            # Check for duplicate ID
            for ev in manifest["evidence"]:
                if ev["evidence_id"] == evd_id:
                    messagebox.showerror("Error", f"Evidence ID '{evd_id}' already exists in manifest.", parent=self)
                    self.btn_submit.config(state="normal", text="Archive & Compute Hash")
                    return

            record = {
                "evidence_id": evd_id,
                "case_id": case_id,
                "original_name": original_name,
                "archived_filename": archive_filename,
                "file_size": file_size,
                "file_size_formatted": format_file_size(file_size),
                "intake_hash": intake_hash,
                "collector": collector,
                "description": desc,
                "timestamp": get_current_timestamp(),
                "master_path": os.path.relpath(master_filepath, BASE_DIR).replace("\\", "/"),
                "working_path": os.path.relpath(working_filepath, BASE_DIR).replace("\\", "/"),
                "status": "Archived",
                "verification_status": "PENDING",
                "last_verified": "Not yet verified"
            }
            manifest["evidence"].append(record)
            save_manifest(manifest)

            # Step 5: Log chain of custody
            log_custody_action(
                evidence_id=evd_id,
                case_id=case_id,
                action="ADDED",
                user_name=collector,
                reason="Initial forensic intake and master/working archive creation",
                details=f"SHA-256: {intake_hash} | Size: {file_size} bytes"
            )

            messagebox.showinfo(
                "Archiving Complete",
                f"Evidence '{evd_id}' successfully archived!\n\n"
                f"• Master Copy: Set to Read-Only\n"
                f"• Working Copy: Ready for analysis\n"
                f"• Intake SHA-256:\n{intake_hash}",
                parent=self
            )

            self.on_success()
            self.destroy()

        except Exception as ex:
            messagebox.showerror("Archiving Failed", f"An error occurred: {ex}", parent=self)
            self.btn_submit.config(state="normal", text="Archive & Compute Hash")


class CustodyLogViewerDialog(tk.Toplevel):
    """Modal dialog displaying the complete Chain of Custody Audit Log."""
    def __init__(self, parent, filter_id=None):
        super().__init__(parent)
        self.title("Chain of Custody Audit Log")
        self.geometry("980x620")
        self.configure(bg=COLOR_BG_APP)
        self.transient(parent)

        self.filter_id = filter_id

        # Center dialog
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 490
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 310
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

        self._build_ui()
        self._load_data()

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=COLOR_BG_HEADER, padx=20, pady=14)
        header.pack(fill="x")

        title_text = f"📋 Chain of Custody Log: {self.filter_id}" if self.filter_id else "📋 Chain of Custody Audit Log (custody_log.csv)"
        tk.Label(header, text=title_text, font=("Segoe UI", 13, "bold"),
                 bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN).pack(side="left")

        # Top Control Row
        filter_bar = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=10)
        filter_bar.pack(fill="x")

        tk.Label(filter_bar, text="Filter by Evidence ID:", font=("Segoe UI", 9, "bold"),
                 bg=COLOR_BG_APP, fg=COLOR_FG_MUTED).pack(side="left", padx=(0, 8))

        self.ent_filter = tk.Entry(filter_bar, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                   insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10), width=24)
        if self.filter_id:
            self.ent_filter.insert(0, self.filter_id)
        self.ent_filter.pack(side="left", ipady=4, padx=(0, 8))
        self.ent_filter.bind("<Return>", lambda e: self._load_data())

        btn_filter = ModernButton(filter_bar, text="Apply Filter", command=self._load_data,
                                  bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="🔍")
        btn_filter.pack(side="left", padx=(0, 8))

        btn_reset = ModernButton(filter_bar, text="Show All", command=self._reset_filter,
                                 bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER)
        btn_reset.pack(side="left")

        btn_add_action = ModernButton(filter_bar, text="Record Custody Action", command=self._record_manual_custody,
                                      bg_color=COLOR_BTN_PRIMARY, hover_color=COLOR_BTN_PRIMARY_HOVER, icon="✍️")
        btn_add_action.pack(side="right")

        # Treeview table for logs
        table_frame = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=5)
        table_frame.pack(fill="both", expand=True)

        columns = ("timestamp", "evidence_id", "case_id", "action", "user_name", "reason", "details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("evidence_id", text="Evidence ID")
        self.tree.heading("case_id", text="Case ID")
        self.tree.heading("action", text="Action")
        self.tree.heading("user_name", text="User / Examiner")
        self.tree.heading("reason", text="Reason / Authorization")
        self.tree.heading("details", text="Technical Details / Hashes")

        self.tree.column("timestamp", width=140, anchor="center")
        self.tree.column("evidence_id", width=140, anchor="center")
        self.tree.column("case_id", width=110, anchor="center")
        self.tree.column("action", width=90, anchor="center")
        self.tree.column("user_name", width=130, anchor="w")
        self.tree.column("reason", width=200, anchor="w")
        self.tree.column("details", width=220, anchor="w")

        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Bottom Bar
        bottom = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=12)
        bottom.pack(fill="x")

        self.lbl_count = tk.Label(bottom, text="Loading logs...", font=("Segoe UI", 9),
                                  bg=COLOR_BG_APP, fg=COLOR_FG_MUTED)
        self.lbl_count.pack(side="left")

        btn_close = ModernButton(bottom, text="Close", command=self.destroy,
                                 bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER)
        btn_close.pack(side="right")

    def _reset_filter(self):
        self.ent_filter.delete(0, tk.END)
        self._load_data()

    def _load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        filter_val = self.ent_filter.get().strip() or None
        entries = read_custody_logs(filter_evidence_id=filter_val)

        for entry in reversed(entries):  # Show newest first
            action = entry.get("Action", "").upper()
            tag = "normal"
            if action in ("TAMPERED", "MISMATCH"):
                tag = "tampered"
            elif action in ("ADDED", "VERIFIED"):
                tag = "verified"

            self.tree.insert("", "end", values=(
                entry.get("Timestamp", ""),
                entry.get("Evidence ID", ""),
                entry.get("Case ID", ""),
                entry.get("Action", ""),
                entry.get("User Name", ""),
                entry.get("Reason", ""),
                entry.get("Details", "")
            ), tags=(tag,))

        self.tree.tag_configure("tampered", foreground=COLOR_STATUS_TAMPERED)
        self.tree.tag_configure("verified", foreground=COLOR_STATUS_MATCH)
        self.tree.tag_configure("normal", foreground=COLOR_FG_MAIN)

        self.lbl_count.config(text=f"Total custody records: {len(entries)}")

    def _record_manual_custody(self):
        """Prompt to log an action such as VIEWED, COPIED, or TRANSFERRED."""
        dialog = RecordCustodyActionDialog(self, default_id=self.ent_filter.get().strip())
        self.wait_window(dialog)
        self._load_data()


class RecordCustodyActionDialog(tk.Toplevel):
    """Modal to record a manual chain of custody event (VIEWED, COPIED, TRANSFERRED, etc.)."""
    def __init__(self, parent, default_id=""):
        super().__init__(parent)
        self.title("Log Custody Action")
        self.geometry("520x440")
        self.configure(bg=COLOR_BG_APP)
        self.transient(parent)
        self.grab_set()

        self.default_id = default_id

        # Center dialog
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 260
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 220
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

        self._build_ui()

    def _build_ui(self):
        header = tk.Frame(self, bg=COLOR_BG_HEADER, padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="✍️ Record Chain of Custody Event", font=("Segoe UI", 12, "bold"),
                 bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN).pack(anchor="w")

        form = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=14)
        form.pack(fill="both", expand=True)

        # Evidence ID
        tk.Label(form, text="Evidence ID *", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(anchor="w")
        self.ent_id = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_id.insert(0, self.default_id)
        self.ent_id.pack(fill="x", ipady=4, pady=(2, 8))

        # Action Selector
        tk.Label(form, text="Action Type *", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(anchor="w")
        self.cb_action = ttk.Combobox(form, values=["VIEWED", "COPIED", "ANALYZED", "TRANSFERRED", "COURT PRESENTATION", "DISPOSED"], state="readonly")
        self.cb_action.set("VIEWED")
        self.cb_action.pack(fill="x", ipady=4, pady=(2, 8))

        # User Name
        tk.Label(form, text="Examiner / User Name *", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(anchor="w")
        self.ent_user = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_user.insert(0, os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator")))
        self.ent_user.pack(fill="x", ipady=4, pady=(2, 8))

        # Reason
        tk.Label(form, text="Reason / Authorization *", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(anchor="w")
        self.ent_reason = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_reason.insert(0, "Forensic examination and verification")
        self.ent_reason.pack(fill="x", ipady=4, pady=(2, 8))

        # Details
        tk.Label(form, text="Technical Details / Notes", font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(anchor="w")
        self.ent_details = tk.Entry(form, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 10))
        self.ent_details.pack(fill="x", ipady=4, pady=(2, 16))

        # Buttons
        btn_row = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=10)
        btn_row.pack(side="bottom", fill="x")

        ModernButton(btn_row, text="Cancel", command=self.destroy,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER).pack(side="right", padx=(8, 0))

        ModernButton(btn_row, text="Save to Log", command=self._save,
                     bg_color=COLOR_BTN_PRIMARY, hover_color=COLOR_BTN_PRIMARY_HOVER, icon="💾").pack(side="right")

    def _save(self):
        evd_id = self.ent_id.get().strip()
        action = self.cb_action.get().strip()
        user = self.ent_user.get().strip()
        reason = self.ent_reason.get().strip()
        details = self.ent_details.get().strip()

        if not evd_id:
            messagebox.showerror("Error", "Evidence ID is required.", parent=self)
            return
        if not user:
            messagebox.showerror("Error", "User name is required.", parent=self)
            return

        # Find case ID from manifest if possible
        manifest = load_manifest()
        case_id = "UNKNOWN"
        for ev in manifest["evidence"]:
            if ev["evidence_id"] == evd_id:
                case_id = ev["case_id"]
                break

        log_custody_action(
            evidence_id=evd_id,
            case_id=case_id,
            action=action,
            user_name=user,
            reason=reason,
            details=details
        )
        self.destroy()


class EvidenceDetailsDialog(tk.Toplevel):
    """Forensic Inspector window to view all metadata, hashes, and custody history for an item."""
    def __init__(self, parent, item_data, on_verify_single_callback):
        super().__init__(parent)
        self.title(f"Forensic Evidence Inspector - {item_data['evidence_id']}")
        self.geometry("740x680")
        self.configure(bg=COLOR_BG_APP)
        self.transient(parent)

        self.item_data = item_data
        self.on_verify = on_verify_single_callback

        # Center dialog
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 370
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 340
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=COLOR_BG_HEADER, padx=20, pady=14)
        header.pack(fill="x")

        status = self.item_data.get("verification_status", "PENDING")
        status_color = COLOR_STATUS_MATCH if status == "MATCH" else (COLOR_STATUS_TAMPERED if status == "TAMPERED" else COLOR_STATUS_PENDING)

        tk.Label(header, text=f"🔍 Evidence Inspector: {self.item_data['evidence_id']}",
                 font=("Segoe UI", 13, "bold"), bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN).pack(side="left")

        badge = tk.Label(header, text=f" {status} ", font=("Segoe UI", 10, "bold"),
                         bg=status_color, fg="#ffffff", padx=8, pady=2)
        badge.pack(side="right")

        # Scrollable container
        canvas = tk.Canvas(self, bg=COLOR_BG_APP, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=COLOR_BG_APP, padx=20, pady=16)

        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas_window = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Properties Table
        props = [
            ("Evidence ID:", self.item_data.get("evidence_id")),
            ("Case ID:", self.item_data.get("case_id")),
            ("Original Filename:", self.item_data.get("original_name")),
            ("File Size:", f"{self.item_data.get('file_size_formatted')} ({self.item_data.get('file_size', 0):,} bytes)"),
            ("Intake Date/Time:", self.item_data.get("timestamp")),
            ("Collector / Custodian:", self.item_data.get("collector")),
            ("Archived Master Path:", self.item_data.get("master_path")),
            ("Working Copy Path:", self.item_data.get("working_path")),
            ("Last Verification:", self.item_data.get("last_verified", "Never")),
            ("Integrity Status:", status),
            ("Case Description:", self.item_data.get("description"))
        ]

        for lbl, val in props:
            row = tk.Frame(body, bg=COLOR_BG_CARD, padx=12, pady=6, highlightthickness=1, highlightbackground=COLOR_BORDER)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=lbl, font=("Segoe UI", 9, "bold"), bg=COLOR_BG_CARD, fg=COLOR_FG_MUTED, width=22, anchor="w").pack(side="left")
            tk.Label(row, text=str(val), font=("Segoe UI", 9), bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, anchor="w", wraplength=480, justify="left").pack(side="left", fill="x", expand=True)

        # Cryptographic Hash Section
        hash_box = tk.LabelFrame(body, text=" 🔐 Cryptographic Hash Verification (SHA-256) ",
                                 font=("Segoe UI", 10, "bold"), bg=COLOR_BG_APP, fg=COLOR_FG_ACCENT, padx=14, pady=12)
        hash_box.pack(fill="x", pady=(14, 10))

        tk.Label(hash_box, text="Intake Hash (Computed at Evidence Ingestion):", font=("Segoe UI", 9, "bold"),
                 bg=COLOR_BG_APP, fg=COLOR_FG_MUTED).pack(anchor="w")

        intake_hash = self.item_data.get("intake_hash", "")
        hash_frame1 = tk.Frame(hash_box, bg=COLOR_BG_CARD, padx=8, pady=6)
        hash_frame1.pack(fill="x", pady=(2, 8))

        lbl_intake_hash = tk.Label(hash_frame1, text=intake_hash, font=("Consolas", 10),
                                   bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN, anchor="w", wraplength=580)
        lbl_intake_hash.pack(side="left", fill="x", expand=True)

        btn_copy_intake = ModernButton(hash_frame1, text="Copy", command=lambda: self._copy_to_clipboard(intake_hash),
                                       bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER)
        btn_copy_intake.pack(side="right")

        # Master file read-only check
        master_abs = os.path.join(BASE_DIR, self.item_data.get("master_path", ""))
        is_readonly = False
        if os.path.exists(master_abs):
            mode = os.stat(master_abs).st_mode
            is_readonly = not (mode & stat.S_IWRITE)

        ro_text = "Master File Read-Only: YES (Protected from accidental tampering)" if is_readonly else "Master File Read-Only: NO (Warning: Writable)"
        ro_color = COLOR_STATUS_MATCH if is_readonly else COLOR_STATUS_TAMPERED
        tk.Label(hash_box, text=ro_text, font=("Segoe UI", 9, "bold"), bg=COLOR_BG_APP, fg=ro_color).pack(anchor="w", pady=(4, 0))

        # Bottom Buttons
        bottom_bar = tk.Frame(self, bg=COLOR_BG_APP, padx=20, pady=12)
        bottom_bar.pack(side="bottom", fill="x")

        ModernButton(bottom_bar, text="Close", command=self.destroy,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER).pack(side="right", padx=(8, 0))

        ModernButton(bottom_bar, text="Open Working Copy", command=self._open_working_copy,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📂").pack(side="right", padx=(8, 0))

        ModernButton(bottom_bar, text="View Custody Log", command=self._view_custody,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📋").pack(side="right", padx=(8, 0))

        ModernButton(bottom_bar, text="Verify Integrity Now", command=self._verify_now,
                     bg_color=COLOR_BTN_PRIMARY, hover_color=COLOR_BTN_PRIMARY_HOVER, icon="🔍").pack(side="right")

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard.", parent=self)

    def _open_working_copy(self):
        working_rel = self.item_data.get("working_path")
        if not working_rel:
            return
        abs_path = os.path.join(BASE_DIR, working_rel)
        if not os.path.exists(abs_path):
            messagebox.showerror("Error", f"Working copy file not found at: {abs_path}", parent=self)
            return

        # Open file or containing folder
        try:
            if sys.platform == "win32":
                os.startfile(os.path.dirname(abs_path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", os.path.dirname(abs_path)])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(abs_path)])

            log_custody_action(
                evidence_id=self.item_data["evidence_id"],
                case_id=self.item_data["case_id"],
                action="VIEWED",
                user_name=os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator")),
                reason="Opened working folder for forensic analysis",
                details=f"Path: {abs_path}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory: {e}", parent=self)

    def _view_custody(self):
        CustodyLogViewerDialog(self, filter_id=self.item_data["evidence_id"])

    def _verify_now(self):
        self.destroy()
        self.on_verify(self.item_data["evidence_id"])


# ==============================================================================
# MAIN APPLICATION CONTROLLER
# ==============================================================================

class DigitalEvidenceArchivingApp(tk.Tk):
    """
    Main forensic desktop interface with dark theme, sidebar navigation,
    dashboard summary metrics, evidence table, and report generation.
    """
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} - {APP_VERSION}")
        self.geometry("1240x780")
        self.minsize(1050, 650)
        self.configure(bg=COLOR_BG_APP)

        # Apply system & ttk styles
        self._setup_styles()

        # Build Main View Layout
        self._build_header()
        self._build_body_layout()
        self._build_status_bar()

        # Load initial manifest and refresh counts
        self.refresh_all_data()

    def _setup_styles(self):
        """Configure ttk widgets for seamless dark theme presentation."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Configure Treeview styling
        style.configure(
            "Treeview",
            background=COLOR_BG_APP,
            foreground=COLOR_FG_MAIN,
            fieldbackground=COLOR_BG_APP,
            rowheight=32,
            font=("Segoe UI", 9),
            borderwidth=0
        )
        style.map(
            "Treeview",
            background=[("selected", "#1f6feb")],
            foreground=[("selected", "#ffffff")]
        )

        style.configure(
            "Treeview.Heading",
            background=COLOR_BG_CARD,
            foreground=COLOR_FG_MAIN,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padding=6
        )
        style.map(
            "Treeview.Heading",
            background=[("active", COLOR_BORDER)]
        )

        # Scrollbars
        style.configure(
            "Vertical.TScrollbar",
            background=COLOR_BG_CARD,
            troughcolor=COLOR_BG_APP,
            bordercolor=COLOR_BG_APP,
            arrowcolor=COLOR_FG_MUTED,
            relief="flat"
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=COLOR_BG_CARD,
            troughcolor=COLOR_BG_APP,
            bordercolor=COLOR_BG_APP,
            arrowcolor=COLOR_FG_MUTED,
            relief="flat"
        )

        # Combobox styling
        style.configure(
            "TCombobox",
            fieldbackground=COLOR_BG_CARD,
            background=COLOR_BG_CARD,
            foreground=COLOR_FG_MAIN,
            selectbackground=COLOR_BG_CARD,
            selectforeground=COLOR_FG_MAIN,
            relief="flat"
        )

    def _build_header(self):
        """Top banner with system branding and quick status info."""
        self.header_frame = tk.Frame(self, bg=COLOR_BG_HEADER, height=64, padx=20, pady=10)
        self.header_frame.pack(side="top", fill="x")

        # Left branding
        brand_frame = tk.Frame(self.header_frame, bg=COLOR_BG_HEADER)
        brand_frame.pack(side="left", fill="y")

        lbl_logo = tk.Label(brand_frame, text="🛡️", font=("Segoe UI Emoji", 20), bg=COLOR_BG_HEADER)
        lbl_logo.pack(side="left", padx=(0, 10))

        title_box = tk.Frame(brand_frame, bg=COLOR_BG_HEADER)
        title_box.pack(side="left")

        lbl_title = tk.Label(title_box, text=APP_TITLE, font=("Segoe UI", 14, "bold"),
                             bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN)
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(title_box, text="NIST-Compliant Cryptographic Hash Manifest & Chain of Custody Guardian",
                            font=("Segoe UI", 8), bg=COLOR_BG_HEADER, fg=COLOR_FG_MUTED)
        lbl_sub.pack(anchor="w")

        # Right Active User & System Clock
        right_info = tk.Frame(self.header_frame, bg=COLOR_BG_HEADER)
        right_info.pack(side="right", fill="y")

        self.lbl_clock = tk.Label(right_info, text=get_current_timestamp(), font=("Consolas", 10),
                                  bg=COLOR_BG_HEADER, fg=COLOR_FG_ACCENT)
        self.lbl_clock.pack(anchor="e")
        self._update_clock()

        current_user = os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator"))
        lbl_user = tk.Label(right_info, text=f"👤 Session: {current_user}", font=("Segoe UI", 8),
                            bg=COLOR_BG_HEADER, fg=COLOR_FG_MUTED)
        lbl_user.pack(anchor="e", pady=(2, 0))

    def _update_clock(self):
        """Auto-update top right timestamp every second."""
        self.lbl_clock.config(text=get_current_timestamp())
        self.after(1000, self._update_clock)

    def _build_body_layout(self):
        """Construct the sidebar actions and main dashboard / table workspace."""
        self.body_container = tk.Frame(self, bg=COLOR_BG_APP)
        self.body_container.pack(fill="both", expand=True)

        # -----------------------------
        # Left Sidebar
        # -----------------------------
        self.sidebar = tk.Frame(self.body_container, bg=COLOR_BG_SIDEBAR, width=240, padx=14, pady=16)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="ACTIONS & TOOLS", font=("Segoe UI", 8, "bold"),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_MUTED).pack(anchor="w", pady=(0, 10))

        # Action Buttons
        ModernButton(self.sidebar, text="Add Evidence", command=self._action_add_evidence,
                     bg_color=COLOR_BTN_PRIMARY, hover_color=COLOR_BTN_PRIMARY_HOVER, icon="➕").pack(fill="x", pady=4)

        ModernButton(self.sidebar, text="Verify Integrity", command=self._action_verify_all,
                     bg_color="#1f6feb", hover_color="#388bfd", icon="🔍").pack(fill="x", pady=4)

        ModernButton(self.sidebar, text="Chain of Custody", command=self._action_view_custody,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📋").pack(fill="x", pady=4)

        ModernButton(self.sidebar, text="Export Reports", command=self._action_export_reports,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📑").pack(fill="x", pady=4)

        ModernButton(self.sidebar, text="Open Archive Dir", command=self._action_open_archive_dir,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="📁").pack(fill="x", pady=4)

        tk.Frame(self.sidebar, bg=COLOR_BORDER, height=1).pack(fill="x", pady=14)

        tk.Label(self.sidebar, text="DEMO & TESTING", font=("Segoe UI", 8, "bold"),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_MUTED).pack(anchor="w", pady=(0, 8))

        ModernButton(self.sidebar, text="Simulate Tamper", command=self._action_simulate_tamper,
                     bg_color=COLOR_BTN_DANGER, hover_color=COLOR_BTN_DANGER_HOVER, icon="⚠️").pack(fill="x", pady=4)

        ModernButton(self.sidebar, text="Clear Results", command=self._action_clear_results,
                     bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="🧹").pack(fill="x", pady=4)

        # Quick summary stats in sidebar bottom
        sidebar_bottom = tk.Frame(self.sidebar, bg=COLOR_BG_SIDEBAR)
        sidebar_bottom.pack(side="bottom", fill="x")

        tk.Label(sidebar_bottom, text="MANIFEST FILE:", font=("Segoe UI", 8, "bold"),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_MUTED).pack(anchor="w")
        tk.Label(sidebar_bottom, text="archive_manifest.json", font=("Consolas", 8),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_ACCENT).pack(anchor="w", pady=(0, 6))

        tk.Label(sidebar_bottom, text="CUSTODY AUDIT:", font=("Segoe UI", 8, "bold"),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_MUTED).pack(anchor="w")
        tk.Label(sidebar_bottom, text="custody_log.csv", font=("Consolas", 8),
                 bg=COLOR_BG_SIDEBAR, fg=COLOR_FG_ACCENT).pack(anchor="w")

        # -----------------------------
        # Main Content Area
        # -----------------------------
        self.main_content = tk.Frame(self.body_container, bg=COLOR_BG_APP, padx=18, pady=16)
        self.main_content.pack(side="right", fill="both", expand=True)

        # 1. Dashboard Metric Cards
        self._build_dashboard_cards()

        # 2. Table Controls & Search Filter
        self._build_table_controls()

        # 3. Evidence Table View
        self._build_table_view()

    def _build_dashboard_cards(self):
        """Top cards showing Total Evidence, Archived, Verified OK, and Tampered counts."""
        cards_frame = tk.Frame(self.main_content, bg=COLOR_BG_APP)
        cards_frame.pack(fill="x", pady=(0, 16))

        # 4 Responsive grid columns
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.columnconfigure(2, weight=1)
        cards_frame.columnconfigure(3, weight=1)

        self.card_total = StatCard(cards_frame, title="Total Evidence", initial_val="0",
                                   accent_color="#58a6ff", icon="📦")
        self.card_total.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.card_archived = StatCard(cards_frame, title="Archived", initial_val="0",
                                      accent_color="#a371f7", icon="💾")
        self.card_archived.grid(row=0, column=1, sticky="nsew", padx=4)

        self.card_verified = StatCard(cards_frame, title="Verified OK", initial_val="0",
                                      accent_color=COLOR_STATUS_MATCH, icon="✅")
        self.card_verified.grid(row=0, column=2, sticky="nsew", padx=4)

        self.card_tampered = StatCard(cards_frame, title="Tampered", initial_val="0",
                                      accent_color=COLOR_STATUS_TAMPERED, icon="🚨")
        self.card_tampered.grid(row=0, column=3, sticky="nsew", padx=(8, 0))

    def _build_table_controls(self):
        """Search box and filter controls for the evidence table."""
        control_bar = tk.Frame(self.main_content, bg=COLOR_BG_APP)
        control_bar.pack(fill="x", pady=(0, 10))

        # Title
        tk.Label(control_bar, text="Archived Evidence Inventory", font=("Segoe UI", 11, "bold"),
                 bg=COLOR_BG_APP, fg=COLOR_FG_MAIN).pack(side="left")

        # Right-aligned search and filter
        filter_box = tk.Frame(control_bar, bg=COLOR_BG_APP)
        filter_box.pack(side="right")

        tk.Label(filter_box, text="Search:", font=("Segoe UI", 9), bg=COLOR_BG_APP, fg=COLOR_FG_MUTED).pack(side="left", padx=(0, 4))
        self.ent_search = tk.Entry(filter_box, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                   insertbackground=COLOR_FG_MAIN, relief="flat", font=("Segoe UI", 9), width=20)
        self.ent_search.pack(side="left", ipady=3, padx=(0, 10))
        self.ent_search.bind("<KeyRelease>", lambda e: self._filter_table())

        tk.Label(filter_box, text="Filter Status:", font=("Segoe UI", 9), bg=COLOR_BG_APP, fg=COLOR_FG_MUTED).pack(side="left", padx=(0, 4))
        self.cb_filter_status = ttk.Combobox(filter_box, values=["All Statuses", "MATCH", "TAMPERED", "PENDING"], state="readonly", width=14)
        self.cb_filter_status.set("All Statuses")
        self.cb_filter_status.pack(side="left", padx=(0, 8))
        self.cb_filter_status.bind("<<ComboboxSelected>>", lambda e: self._filter_table())

        btn_refresh = ModernButton(filter_box, text="Refresh", command=self.refresh_all_data,
                                   bg_color=COLOR_BTN_DEFAULT, hover_color=COLOR_BTN_DEFAULT_HOVER, icon="🔄")
        btn_refresh.pack(side="left")

    def _build_table_view(self):
        """Interactive table displaying all evidence items with custom coloring."""
        table_container = tk.Frame(self.main_content, bg=COLOR_BG_APP)
        table_container.pack(fill="both", expand=True)

        columns = (
            "evidence_id",
            "case_id",
            "original_name",
            "file_size",
            "intake_hash",
            "collector",
            "timestamp",
            "verification_status"
        )

        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("evidence_id", text="Evidence ID", command=lambda: self._sort_column("evidence_id", False))
        self.tree.heading("case_id", text="Case ID", command=lambda: self._sort_column("case_id", False))
        self.tree.heading("original_name", text="File Name", command=lambda: self._sort_column("original_name", False))
        self.tree.heading("file_size", text="Size", command=lambda: self._sort_column("file_size", False))
        self.tree.heading("intake_hash", text="Intake SHA-256", command=lambda: self._sort_column("intake_hash", False))
        self.tree.heading("collector", text="Collector", command=lambda: self._sort_column("collector", False))
        self.tree.heading("timestamp", text="Intake Timestamp", command=lambda: self._sort_column("timestamp", False))
        self.tree.heading("verification_status", text="Integrity Status", command=lambda: self._sort_column("verification_status", False))

        self.tree.column("evidence_id", width=130, anchor="center")
        self.tree.column("case_id", width=110, anchor="center")
        self.tree.column("original_name", width=160, anchor="w")
        self.tree.column("file_size", width=80, anchor="e")
        self.tree.column("intake_hash", width=160, anchor="center")
        self.tree.column("collector", width=120, anchor="w")
        self.tree.column("timestamp", width=130, anchor="center")
        self.tree.column("verification_status", width=110, anchor="center")

        v_scroll = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        # Double click to inspect
        self.tree.bind("<Double-1>", self._on_double_click_item)

        # Right-click context menu
        self._build_context_menu()
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _build_context_menu(self):
        """Right-click menu for instant item actions."""
        self.context_menu = tk.Menu(self, tearoff=0, bg=COLOR_BG_CARD, fg=COLOR_FG_MAIN,
                                    activebackground="#1f6feb", activeforeground="#ffffff",
                                    font=("Segoe UI", 9))
        self.context_menu.add_command(label="🔍 Inspect Evidence Details", command=self._action_inspect_selected)
        self.context_menu.add_command(label="🔒 Verify This Item Integrity", command=self._action_verify_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 View Custody History", command=self._action_view_selected_custody)
        self.context_menu.add_command(label="📂 Open Working Copy", command=self._action_open_working_selected)
        self.context_menu.add_command(label="📋 Copy SHA-256 Hash", command=self._action_copy_hash_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⚠️ Simulate Tamper (Test Detection)", command=self._action_simulate_tamper_selected)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _build_status_bar(self):
        """Bottom status bar showing latest activity and system state."""
        self.status_bar = tk.Frame(self, bg=COLOR_BG_HEADER, height=28, padx=16, pady=4)
        self.status_bar.pack(side="bottom", fill="x")

        self.lbl_status = tk.Label(self.status_bar, text="Ready. System initialized.",
                                   font=("Segoe UI", 9), bg=COLOR_BG_HEADER, fg=COLOR_FG_MAIN)
        self.lbl_status.pack(side="left")

        self.lbl_manifest_info = tk.Label(self.status_bar, text="Storage: archive_manifest.json | custody_log.csv",
                                          font=("Consolas", 8), bg=COLOR_BG_HEADER, fg=COLOR_FG_MUTED)
        self.lbl_manifest_info.pack(side="right")

    def set_status(self, message, is_error=False, is_success=False):
        """Update bottom status message with visual indicator."""
        color = COLOR_STATUS_TAMPERED if is_error else (COLOR_STATUS_MATCH if is_success else COLOR_FG_MAIN)
        self.lbl_status.config(text=message, fg=color)

    # ==========================================================================
    # DATA REFRESH & FILTERING
    # ==========================================================================

    def refresh_all_data(self):
        """Reload manifest, update cards, and populate table."""
        manifest = load_manifest()
        evidence_list = manifest.get("evidence", [])

        # Calculate counts
        total_count = len(evidence_list)
        archived_count = sum(1 for e in evidence_list if e.get("status") == "Archived")
        verified_count = sum(1 for e in evidence_list if e.get("verification_status") == "MATCH")
        tampered_count = sum(1 for e in evidence_list if e.get("verification_status") == "TAMPERED")

        # Update cards
        self.card_total.update_value(total_count)
        self.card_archived.update_value(archived_count)
        self.card_verified.update_value(verified_count)
        self.card_tampered.update_value(tampered_count)

        self._filter_table(evidence_list)
        self.set_status(f"Manifest loaded: {total_count} evidence items recorded.")

    def _filter_table(self, evidence_list=None):
        """Filter table rows based on search text and status combobox."""
        if evidence_list is None:
            manifest = load_manifest()
            evidence_list = manifest.get("evidence", [])

        search_query = self.ent_search.get().strip().lower()
        status_filter = self.cb_filter_status.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for ev in evidence_list:
            ev_id = ev.get("evidence_id", "")
            case_id = ev.get("case_id", "")
            orig_name = ev.get("original_name", "")
            collector = ev.get("collector", "")
            ver_status = ev.get("verification_status", "PENDING")

            # Check status filter
            if status_filter != "All Statuses" and ver_status != status_filter:
                continue

            # Check text search
            if search_query:
                combined_text = f"{ev_id} {case_id} {orig_name} {collector} {ver_status}".lower()
                if search_query not in combined_text:
                    continue

            # Display truncated hash in table for readability
            raw_hash = ev.get("intake_hash", "")
            short_hash = f"{raw_hash[:8]}...{raw_hash[-8:]}" if len(raw_hash) > 16 else raw_hash

            # Insert row
            item_id = self.tree.insert("", "end", values=(
                ev_id,
                case_id,
                orig_name,
                ev.get("file_size_formatted", format_file_size(ev.get("file_size", 0))),
                short_hash,
                collector,
                ev.get("timestamp", ""),
                ver_status
            ), tags=(ver_status,))

        # Tag formatting
        self.tree.tag_configure("MATCH", foreground=COLOR_STATUS_MATCH)
        self.tree.tag_configure("TAMPERED", foreground=COLOR_STATUS_TAMPERED, font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("PENDING", foreground=COLOR_STATUS_PENDING)

    def _sort_column(self, col, reverse):
        """Sort table rows by clicked column header."""
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            # Try numeric sort if possible
            data.sort(key=lambda t: float(t[0].split()[0]), reverse=reverse)
        except Exception:
            data.sort(reverse=reverse)

        for index, (val, k) in enumerate(data):
            self.tree.move(k, "", index)

        self.tree.heading(col, command=lambda: self._sort_column(col, not reverse))

    def _get_selected_item_data(self):
        """Return the manifest dict for the currently selected table row."""
        selected = self.tree.selection()
        if not selected:
            return None
        values = self.tree.item(selected[0], "values")
        if not values:
            return None
        ev_id = values[0]

        manifest = load_manifest()
        for ev in manifest.get("evidence", []):
            if ev.get("evidence_id") == ev_id:
                return ev
        return None

    # ==========================================================================
    # ACTION HANDLERS
    # ==========================================================================

    def _action_add_evidence(self):
        """Open the Add Evidence intake dialog."""
        AddEvidenceDialog(self, on_success_callback=self.refresh_all_data)

    def _action_verify_all(self):
        """
        Re-hash all archived master files in 1 MB chunks and compare with manifest.
        Update status to MATCH or TAMPERED.
        """
        manifest = load_manifest()
        evidence_list = manifest.get("evidence", [])

        if not evidence_list:
            messagebox.showinfo("Verify Integrity", "No evidence records found to verify.", parent=self)
            return

        user_name = os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator"))
        self.set_status("Verifying cryptographic integrity of all archived files...")
        self.update_idletasks()

        matches = 0
        tampered = 0
        now_ts = get_current_timestamp()

        for ev in evidence_list:
            master_rel = ev.get("master_path", "")
            master_abs = os.path.join(BASE_DIR, master_rel)
            expected_hash = ev.get("intake_hash", "")
            ev_id = ev.get("evidence_id", "")
            case_id = ev.get("case_id", "")

            if not os.path.exists(master_abs):
                ev["verification_status"] = "TAMPERED"
                ev["last_verified"] = now_ts
                tampered += 1
                log_custody_action(
                    evidence_id=ev_id,
                    case_id=case_id,
                    action="VERIFIED",
                    user_name=user_name,
                    reason="Integrity Verification Check",
                    details=f"TAMPERED - Master file missing at {master_rel}"
                )
                continue

            try:
                # Re-compute SHA-256 in 1 MB chunks
                current_hash = calculate_sha256(master_abs, chunk_size=CHUNK_SIZE)
                if current_hash.lower() == expected_hash.lower():
                    ev["verification_status"] = "MATCH"
                    ev["last_verified"] = now_ts
                    matches += 1
                    log_custody_action(
                        evidence_id=ev_id,
                        case_id=case_id,
                        action="VERIFIED",
                        user_name=user_name,
                        reason="Integrity Verification Check",
                        details=f"MATCH - Cryptographic hash confirmed: {current_hash}"
                    )
                else:
                    ev["verification_status"] = "TAMPERED"
                    ev["last_verified"] = now_ts
                    tampered += 1
                    log_custody_action(
                        evidence_id=ev_id,
                        case_id=case_id,
                        action="VERIFIED",
                        user_name=user_name,
                        reason="Integrity Verification Check",
                        details=f"TAMPERED - Hash mismatch! Expected: {expected_hash} | Actual: {current_hash}"
                    )
            except Exception as e:
                ev["verification_status"] = "TAMPERED"
                ev["last_verified"] = now_ts
                tampered += 1
                log_custody_action(
                    evidence_id=ev_id,
                    case_id=case_id,
                    action="VERIFIED",
                    user_name=user_name,
                    reason="Integrity Verification Check",
                    details=f"TAMPERED - Verification error: {e}"
                )

        save_manifest(manifest)
        self.refresh_all_data()

        if tampered > 0:
            self.set_status(f"Integrity check complete: {matches} MATCH, {tampered} TAMPERED!", is_error=True)
            messagebox.showwarning(
                "Integrity Alert: Tampering Detected!",
                f"Verification Results:\n\n"
                f"• Verified OK (MATCH): {matches}\n"
                f"• TAMPERED / Mismatch: {tampered}\n\n"
                f"Please inspect the red rows in the inventory table and audit custody_log.csv.",
                parent=self
            )
        else:
            self.set_status(f"Integrity check passed: All {matches} archived files MATCH their intake hash.", is_success=True)
            messagebox.showinfo(
                "Integrity Verification Passed",
                f"All {matches} evidence items successfully verified!\n\n"
                f"Every archived master file matches its original intake SHA-256 hash perfectly.",
                parent=self
            )

    def _verify_single_item(self, ev_id):
        """Verify the cryptographic integrity of a single evidence item."""
        manifest = load_manifest()
        found_ev = None
        for ev in manifest.get("evidence", []):
            if ev.get("evidence_id") == ev_id:
                found_ev = ev
                break

        if not found_ev:
            messagebox.showerror("Error", f"Item '{ev_id}' not found.", parent=self)
            return

        master_rel = found_ev.get("master_path", "")
        master_abs = os.path.join(BASE_DIR, master_rel)
        expected_hash = found_ev.get("intake_hash", "")
        user_name = os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator"))
        now_ts = get_current_timestamp()

        if not os.path.exists(master_abs):
            found_ev["verification_status"] = "TAMPERED"
            found_ev["last_verified"] = now_ts
            save_manifest(manifest)
            self.refresh_all_data()
            log_custody_action(ev_id, found_ev["case_id"], "VERIFIED", user_name,
                               "Single Verification Check", f"TAMPERED - Master file missing at {master_rel}")
            messagebox.showerror("Tampered", f"Master file for {ev_id} is missing!", parent=self)
            return

        try:
            current_hash = calculate_sha256(master_abs, chunk_size=CHUNK_SIZE)
            if current_hash.lower() == expected_hash.lower():
                found_ev["verification_status"] = "MATCH"
                found_ev["last_verified"] = now_ts
                save_manifest(manifest)
                self.refresh_all_data()
                log_custody_action(ev_id, found_ev["case_id"], "VERIFIED", user_name,
                                   "Single Verification Check", f"MATCH - SHA-256: {current_hash}")
                messagebox.showinfo(
                    "Verification: MATCH",
                    f"Evidence ID: {ev_id}\n\n"
                    f"Result: MATCH (Integrity Intact)\n"
                    f"Current Hash:\n{current_hash}\n\n"
                    f"Matches intake manifest perfectly.",
                    parent=self
                )
            else:
                found_ev["verification_status"] = "TAMPERED"
                found_ev["last_verified"] = now_ts
                save_manifest(manifest)
                self.refresh_all_data()
                log_custody_action(ev_id, found_ev["case_id"], "VERIFIED", user_name,
                                   "Single Verification Check", f"TAMPERED - Hash mismatch! Current: {current_hash}")
                messagebox.showerror(
                    "Verification: TAMPERED",
                    f"CRITICAL WARNING for {ev_id}!\n\n"
                    f"Result: TAMPERED (Hash Mismatch)\n"
                    f"Expected Intake Hash:\n{expected_hash}\n\n"
                    f"Current Master Hash:\n{current_hash}",
                    parent=self
                )
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify file: {e}", parent=self)

    def _action_view_custody(self):
        """Open custody log viewer for all records."""
        CustodyLogViewerDialog(self)

    def _action_export_reports(self):
        """
        Generate comprehensive forensic archive reports:
        1. archive_report.json: structured JSON report with evidence & embedded custody logs
        2. archive_report.csv: tabular CSV report for spreadsheet presentation
        """
        manifest = load_manifest()
        evidence_list = manifest.get("evidence", [])
        all_custody = read_custody_logs()
        user_name = os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator"))
        export_time = get_current_timestamp()

        # Build JSON report
        report_data = {
            "report_title": "Digital Evidence Archive & Integrity Report",
            "generated_at": export_time,
            "generated_by": user_name,
            "summary": {
                "total_evidence_items": len(evidence_list),
                "verified_match_count": sum(1 for e in evidence_list if e.get("verification_status") == "MATCH"),
                "tampered_count": sum(1 for e in evidence_list if e.get("verification_status") == "TAMPERED"),
                "pending_verification": sum(1 for e in evidence_list if e.get("verification_status") == "PENDING"),
                "total_custody_actions_logged": len(all_custody)
            },
            "evidence_inventory": []
        }

        for ev in evidence_list:
            ev_copy = dict(ev)
            # Embed item's specific custody entries
            ev_copy["custody_history"] = [
                c for c in all_custody if c.get("Evidence ID") == ev.get("evidence_id")
            ]
            report_data["evidence_inventory"].append(ev_copy)

        try:
            # Write archive_report.json
            with open(REPORT_JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)

            # Write archive_report.csv
            csv_fields = [
                "Evidence ID", "Case ID", "File Name", "Size (Bytes)", "Formatted Size",
                "Intake SHA-256", "Collector", "Intake Timestamp", "Verification Status",
                "Last Verified", "Master Path", "Working Path", "Total Custody Events", "Description"
            ]

            with open(REPORT_CSV_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=csv_fields)
                writer.writeheader()
                for ev in evidence_list:
                    ev_custody_count = sum(1 for c in all_custody if c.get("Evidence ID") == ev.get("evidence_id"))
                    writer.writerow({
                        "Evidence ID": ev.get("evidence_id"),
                        "Case ID": ev.get("case_id"),
                        "File Name": ev.get("original_name"),
                        "Size (Bytes)": ev.get("file_size"),
                        "Formatted Size": ev.get("file_size_formatted"),
                        "Intake SHA-256": ev.get("intake_hash"),
                        "Collector": ev.get("collector"),
                        "Intake Timestamp": ev.get("timestamp"),
                        "Verification Status": ev.get("verification_status"),
                        "Last Verified": ev.get("last_verified"),
                        "Master Path": ev.get("master_path"),
                        "Working Path": ev.get("working_path"),
                        "Total Custody Events": ev_custody_count,
                        "Description": ev.get("description")
                    })

            # Log this export event in custody log
            log_custody_action(
                evidence_id="ALL",
                case_id="SYSTEM",
                action="EXPORTED",
                user_name=user_name,
                reason="Generated formal archive audit reports",
                details=f"Generated archive_report.json and archive_report.csv with {len(evidence_list)} evidence items."
            )

            self.set_status("Forensic reports exported: archive_report.json and archive_report.csv", is_success=True)
            messagebox.showinfo(
                "Reports Exported Successfully",
                f"Forensic reports have been generated in the project root:\n\n"
                f"1. {os.path.basename(REPORT_JSON_FILE)}\n"
                f"   (Detailed JSON with embedded custody audit histories)\n\n"
                f"2. {os.path.basename(REPORT_CSV_FILE)}\n"
                f"   (Tabular CSV report for spreadsheet analysis)\n\n"
                f"Action logged to custody_log.csv.",
                parent=self
            )

        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export reports: {e}", parent=self)

    def _action_open_archive_dir(self):
        """Open the base archive folder in system file manager."""
        try:
            if sys.platform == "win32":
                os.startfile(ARCHIVE_ROOT)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", ARCHIVE_ROOT])
            else:
                subprocess.Popen(["xdg-open", ARCHIVE_ROOT])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open archive directory: {e}", parent=self)

    def _action_clear_results(self):
        """Reset search filters and reset verification status in the current view."""
        self.ent_search.delete(0, tk.END)
        self.cb_filter_status.set("All Statuses")
        self.refresh_all_data()
        self.set_status("Filter and view reset.")

    def _action_simulate_tamper(self):
        """Interactive tool to intentionally modify an archived file to test tamper detection."""
        manifest = load_manifest()
        evidence_list = manifest.get("evidence", [])
        if not evidence_list:
            messagebox.showinfo("Simulate Tamper", "No archived evidence available to tamper.", parent=self)
            return

        item = self._get_selected_item_data()
        if not item:
            item = evidence_list[0]

        ev_id = item["evidence_id"]
        master_rel = item.get("master_path")
        master_abs = os.path.join(BASE_DIR, master_rel)

        confirm = messagebox.askyesno(
            "Simulate Evidence Tampering",
            f"This will intentionally inject 1 altered byte into the master copy of:\n\n"
            f"• Evidence ID: {ev_id}\n"
            f"• File: {master_rel}\n\n"
            f"This demonstrates how the SHA-256 cryptographic integrity verification detects tampering.\n\n"
            f"Proceed with tampering simulation?",
            parent=self
        )
        if not confirm:
            return

        try:
            # Master file is read-only, temporarily lift read-only to simulate malicious or accidental tampering
            set_file_writable(master_abs)
            with open(master_abs, "ab") as f:
                f.write(b"\x00_TAMPERED_BYTE_")
            # Restore read-only flag
            set_file_readonly(master_abs)

            # Record in custody log
            log_custody_action(
                evidence_id=ev_id,
                case_id=item["case_id"],
                action="TAMPERED",
                user_name="Tamper Simulation Tool",
                reason="Forensic testing of integrity detection mechanism",
                details="Injected unauthorized test bytes into master copy"
            )

            messagebox.showwarning(
                "Tampering Injected",
                f"Unauthorized bytes were appended to:\n{master_rel}\n\n"
                f"Now click 'Verify Integrity' or right-click > 'Verify This Item' to see the TAMPERED alert (Red)!",
                parent=self
            )
            self.set_status(f"Simulated tamper injected into {ev_id}. Run 'Verify Integrity' to test detection.", is_error=True)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to simulate tamper: {e}", parent=self)

    # ==========================================================================
    # ITEM SELECTION & CONTEXT MENU ACTIONS
    # ==========================================================================

    def _on_double_click_item(self, event):
        self._action_inspect_selected()

    def _action_inspect_selected(self):
        item = self._get_selected_item_data()
        if not item:
            messagebox.showinfo("Select Evidence", "Please select an evidence row to inspect.", parent=self)
            return
        EvidenceDetailsDialog(self, item_data=item, on_verify_single_callback=self._verify_single_item)

    def _action_verify_selected(self):
        item = self._get_selected_item_data()
        if not item:
            messagebox.showinfo("Select Evidence", "Please select an evidence row to verify.", parent=self)
            return
        self._verify_single_item(item["evidence_id"])

    def _action_view_selected_custody(self):
        item = self._get_selected_item_data()
        if not item:
            messagebox.showinfo("Select Evidence", "Please select an evidence row.", parent=self)
            return
        CustodyLogViewerDialog(self, filter_id=item["evidence_id"])

    def _action_open_working_selected(self):
        item = self._get_selected_item_data()
        if not item:
            messagebox.showinfo("Select Evidence", "Please select an evidence row.", parent=self)
            return
        working_rel = item.get("working_path")
        if not working_rel:
            return
        abs_path = os.path.join(BASE_DIR, working_rel)
        if not os.path.exists(abs_path):
            messagebox.showerror("Error", f"Working file not found at: {abs_path}", parent=self)
            return

        try:
            if sys.platform == "win32":
                os.startfile(os.path.dirname(abs_path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", os.path.dirname(abs_path)])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(abs_path)])

            log_custody_action(
                evidence_id=item["evidence_id"],
                case_id=item["case_id"],
                action="VIEWED",
                user_name=os.getenv("USERNAME", os.getenv("USER", "Forensic Investigator")),
                reason="Opened working folder from context menu",
                details=f"Path: {abs_path}"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory: {e}", parent=self)

    def _action_copy_hash_selected(self):
        item = self._get_selected_item_data()
        if not item:
            messagebox.showinfo("Select Evidence", "Please select an evidence row.", parent=self)
            return
        intake_hash = item.get("intake_hash", "")
        self.clipboard_clear()
        self.clipboard_append(intake_hash)
        self.set_status(f"Copied SHA-256 for {item['evidence_id']} to clipboard.")
        messagebox.showinfo("Copied", f"SHA-256 for {item['evidence_id']} copied:\n{intake_hash}", parent=self)

    def _action_simulate_tamper_selected(self):
        self._action_simulate_tamper()


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

def main():
    """Start the Digital Evidence Archiving System."""
    app = DigitalEvidenceArchivingApp()
    app.mainloop()


if __name__ == "__main__":
    main()

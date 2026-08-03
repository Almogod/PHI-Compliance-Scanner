"""Native CustomTkinter Desktop GUI for PHI & PII Compliance Scanner.

Features Emil Kowalski UI polish philosophy (@/emil):
  - Refined, modern color system (Decent slate/indigo tones, zero harsh neon)
  - Interactive metric cards & executive audit status badges
  - Multi-tab workflow: File/Directory Scanner, Database Scanner, Remediation Engine, Export Hub
  - Real-time threaded scanning with live progress bar and status feedback
  - Filterable findings treeview table with search bar and risk badges
  - Remediation modes: Mask (XXXX 1234), Redact ([REDACTED]), Tokenize (TOK-HMAC)
  - Multi-format exporter: CSV, JSON, HTML Dashboard, Executive PDF, AES-GCM Encrypted (.phi)
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

import customtkinter as ctk

from .engine import Finding, ScanEngine
from .pipeline import Pipeline
from .redactor import redact_file, sanitize_text
from .reporter import write_csv, write_html, write_json, write_pdf_summary, write_encrypted

# Configure CustomTkinter default appearance
ctk.set_appearance_mode("System")  # System theme (Light / Dark)
ctk.set_default_color_theme("blue")  # Muted professional indigo/blue theme


class ComplianceScannerGUI(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("PHI & PII Enterprise Compliance Scanner v4.0")
        self.geometry("1180x780")
        self.minsize(1000, 680)

        # State Variables
        self.scan_target_path: Path | None = None
        self.db_uri_val: str = ""
        self.findings: list[Finding] = []
        self.is_scanning: bool = False
        self.engine = ScanEngine()
        self.pipeline = Pipeline()

        # Build UI layout
        self._setup_theme_tokens()
        self._build_header()
        self._build_body()
        self._build_statusbar()

    def _setup_theme_tokens(self) -> None:
        """Emil design system color tokens & typography."""
        self.colors = {
            "card_bg_light": "#ffffff",
            "card_bg_dark": "#1e293b",
            "accent_indigo": "#4f46e5",
            "accent_indigo_hover": "#4338ca",
            "accent_emerald": "#059669",
            "accent_amber": "#d97706",
            "accent_rose": "#e11d48",
            "border_light": "#e2e8f0",
            "border_dark": "#334155",
            "text_muted": "#64748b",
        }

    def _build_header(self) -> None:
        """Top Header with Brand Logo, Title, and Appearance Toggle."""
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("#ffffff", "#0f172a"), height=64)
        self.header_frame.pack(side="top", fill="x")

        # Brand / Title Block
        brand_label = ctk.CTkLabel(
            self.header_frame,
            text="🛡️  PHI Compliance Scanner",
            font=ctk.CTkFont(family="Inter", size=20, weight="bold"),
            text_color=("#0f172a", "#f8fafc"),
        )
        brand_label.pack(side="left", padx=24, pady=16)

        subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="v4.0 Enterprise • Air-Gapped Local Scanner",
            font=ctk.CTkFont(family="Inter", size=12),
            text_color=self.colors["text_muted"],
        )
        subtitle_label.pack(side="left", padx=0, pady=16)

        # Controls on right
        self.mode_switch = ctk.CTkOptionMenu(
            self.header_frame,
            values=["System Theme", "Light Mode", "Dark Mode"],
            command=self._change_appearance_mode,
            width=130,
            height=32,
            font=ctk.CTkFont(family="Inter", size=12),
        )
        self.mode_switch.set("System Theme")
        self.mode_switch.pack(side="right", padx=24, pady=16)

    def _change_appearance_mode(self, mode_str: str) -> None:
        if mode_str == "Light Mode":
            ctk.set_appearance_mode("Light")
        elif mode_str == "Dark Mode":
            ctk.set_appearance_mode("Dark")
        else:
            ctk.set_appearance_mode("System")

    def _build_body(self) -> None:
        """Main Content Area with Metrics, Tabview, and Action Controls."""
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(side="top", fill="both", expand=True, padx=24, pady=16)

        # 1. Top Metrics Grid
        self.metrics_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.metrics_frame.pack(side="top", fill="x", pady=(0, 16))

        self.metric_cards = {}
        metrics_data = [
            ("Total Findings", "0", "#4f46e5"),
            ("High Risk Exposures", "0", "#e11d48"),
            ("Sources Affected", "0", "#0284c7"),
            ("Compliance Status", "READY", "#059669"),
        ]

        for idx, (title, val, color) in enumerate(metrics_data):
            card = ctk.CTkFrame(self.metrics_frame, corner_radius=12, border_width=1, border_color=("#e2e8f0", "#334155"))
            card.grid(row=0, column=idx, padx=6 if idx > 0 else 0, sticky="ew")
            self.metrics_frame.columnconfigure(idx, weight=1)

            lbl_title = ctk.CTkLabel(card, text=title.upper(), font=ctk.CTkFont(family="Inter", size=11, weight="bold"), text_color=self.colors["text_muted"])
            lbl_title.pack(anchor="w", padx=16, pady=(12, 2))

            lbl_val = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(family="Inter", size=22, weight="bold"), text_color=color)
            lbl_val.pack(anchor="w", padx=16, pady=(0, 12))
            self.metric_cards[title] = lbl_val

        # 2. Main Tabview (File Scanner, Database Scanner, Remediation & Export)
        self.tabview = ctk.CTkTabview(self.main_container, corner_radius=12)
        self.tabview.pack(side="top", fill="both", expand=True)

        self.tab_files = self.tabview.add(" File & Folder Scan ")
        self.tab_db = self.tabview.add(" Read-Only DB Scan ")
        self.tab_remediate = self.tabview.add(" Smart Remediation & Export ")

        self._build_tab_files()
        self._build_tab_db()
        self._build_tab_remediate()

    def _build_tab_files(self) -> None:
        """File & Folder Scanning Tab."""
        control_card = ctk.CTkFrame(self.tab_files, fg_color="transparent")
        control_card.pack(fill="x", padx=16, pady=12)

        self.path_entry = ctk.CTkEntry(
            control_card,
            placeholder_text="Select a file or directory to scan...",
            height=38,
            font=ctk.CTkFont(family="Inter", size=13),
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse_file = ctk.CTkButton(
            control_card,
            text="Choose File",
            height=38,
            width=110,
            command=self._browse_file,
            fg_color="#3b82f6",
            hover_color="#2563eb",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_browse_file.pack(side="left", padx=(0, 8))

        btn_browse_dir = ctk.CTkButton(
            control_card,
            text="Choose Folder",
            height=38,
            width=115,
            command=self._browse_dir,
            fg_color="#64748b",
            hover_color="#475569",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_browse_dir.pack(side="left", padx=(0, 10))

        self.btn_start_scan = ctk.CTkButton(
            control_card,
            text="⚡ Start Scan",
            height=38,
            width=130,
            command=self._start_file_scan,
            fg_color=self.colors["accent_indigo"],
            hover_color=self.colors["accent_indigo_hover"],
            font=ctk.CTkFont(family="Inter", size=13, weight="bold"),
        )
        self.btn_start_scan.pack(side="left")

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.tab_files, height=6)
        self.progress_bar.pack(fill="x", padx=16, pady=(0, 12))
        self.progress_bar.set(0)

        # Findings Results Table
        self._build_findings_table(self.tab_files)

    def _build_tab_db(self) -> None:
        """Database Scanning Tab."""
        control_card = ctk.CTkFrame(self.tab_db, fg_color="transparent")
        control_card.pack(fill="x", padx=16, pady=16)

        lbl_db = ctk.CTkLabel(control_card, text="Database Connection URI:", font=ctk.CTkFont(family="Inter", size=13, weight="bold"))
        lbl_db.pack(anchor="w", pady=(0, 6))

        input_row = ctk.CTkFrame(control_card, fg_color="transparent")
        input_row.pack(fill="x")

        self.db_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="sqlite:///local_database.db or C:\\data\\production.sqlite",
            height=38,
            font=ctk.CTkFont(family="Inter", size=13),
        )
        self.db_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_browse_db = ctk.CTkButton(
            input_row,
            text="Browse SQLite",
            height=38,
            width=120,
            command=self._browse_db,
            fg_color="#64748b",
            hover_color="#475569",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_browse_db.pack(side="left", padx=(0, 10))

        self.btn_db_scan = ctk.CTkButton(
            input_row,
            text="⚡ Scan DB Tables",
            height=38,
            width=140,
            command=self._start_db_scan,
            fg_color=self.colors["accent_indigo"],
            hover_color=self.colors["accent_indigo_hover"],
            font=ctk.CTkFont(family="Inter", size=13, weight="bold"),
        )
        self.btn_db_scan.pack(side="left")

        lbl_info = ctk.CTkLabel(
            control_card,
            text="🔒 Strict Read-Only Guarantee: Database tables are read line-by-line without creating locks or modifying table schemas.",
            font=ctk.CTkFont(family="Inter", size=12),
            text_color=self.colors["text_muted"],
        )
        lbl_info.pack(anchor="w", pady=(10, 0))

        # Progress Bar for DB
        self.db_progress_bar = ctk.CTkProgressBar(self.tab_db, height=6)
        self.db_progress_bar.pack(fill="x", padx=16, pady=(12, 12))
        self.db_progress_bar.set(0)

        # Share findings view with DB tab
        self._build_findings_table(self.tab_db, is_db_tab=True)

    def _build_tab_remediate(self) -> None:
        """Remediation & Export Hub Tab."""
        container = ctk.CTkFrame(self.tab_remediate, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=16)

        # 1. Remediation Section
        rem_card = ctk.CTkFrame(container, corner_radius=12, border_width=1, border_color=("#e2e8f0", "#334155"))
        rem_card.pack(fill="x", pady=(0, 16), ipadx=16, ipady=16)

        lbl_rem_title = ctk.CTkLabel(rem_card, text="Smart File Remediation Engine", font=ctk.CTkFont(family="Inter", size=15, weight="bold"))
        lbl_rem_title.pack(anchor="w", padx=16, pady=(12, 4))

        lbl_rem_desc = ctk.CTkLabel(
            rem_card,
            text="Sanitize sensitive PII attributes in source files using configurable privacy modes.",
            font=ctk.CTkFont(family="Inter", size=12),
            text_color=self.colors["text_muted"],
        )
        lbl_rem_desc.pack(anchor="w", padx=16, pady=(0, 12))

        rem_row = ctk.CTkFrame(rem_card, fg_color="transparent")
        rem_row.pack(fill="x", padx=16, pady=(0, 12))

        lbl_mode = ctk.CTkLabel(rem_row, text="Remediation Mode:", font=ctk.CTkFont(family="Inter", size=13, weight="bold"))
        lbl_mode.pack(side="left", padx=(0, 12))

        self.rem_mode_seg = ctk.CTkSegmentedButton(
            rem_row,
            values=["Mask (XXXX 1234)", "Redact ([REDACTED])", "Tokenize (TOK-HMAC)"],
            font=ctk.CTkFont(family="Inter", size=12),
        )
        self.rem_mode_seg.set("Mask (XXXX 1234)")
        self.rem_mode_seg.pack(side="left", padx=(0, 16))

        btn_remediate_file = ctk.CTkButton(
            rem_row,
            text="🛠️ Remediate File...",
            height=36,
            command=self._execute_remediation,
            fg_color=self.colors["accent_emerald"],
            hover_color="#047857",
            font=ctk.CTkFont(family="Inter", size=13, weight="bold"),
        )
        btn_remediate_file.pack(side="left")

        # 2. Executive Report Export Section
        exp_card = ctk.CTkFrame(container, corner_radius=12, border_width=1, border_color=("#e2e8f0", "#334155"))
        exp_card.pack(fill="x", ipadx=16, ipady=16)

        lbl_exp_title = ctk.CTkLabel(exp_card, text="Executive Audit Export Hub", font=ctk.CTkFont(family="Inter", size=15, weight="bold"))
        lbl_exp_title.pack(anchor="w", padx=16, pady=(12, 4))

        lbl_exp_desc = ctk.CTkLabel(
            exp_card,
            text="Generate auditor-ready compliance summaries and encrypted findings reports.",
            font=ctk.CTkFont(family="Inter", size=12),
            text_color=self.colors["text_muted"],
        )
        lbl_exp_desc.pack(anchor="w", padx=16, pady=(0, 16))

        btn_grid = ctk.CTkFrame(exp_card, fg_color="transparent")
        btn_grid.pack(fill="x", padx=16, pady=(0, 12))

        btn_pdf = ctk.CTkButton(
            btn_grid,
            text="📄 Export Executive PDF Report",
            height=40,
            command=lambda: self._export_report("pdf"),
            fg_color="#e11d48",
            hover_color="#be123c",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_pdf.grid(row=0, column=0, padx=6, pady=6, sticky="ew")

        btn_html = ctk.CTkButton(
            btn_grid,
            text="🌐 Export Interactive HTML Dashboard",
            height=40,
            command=lambda: self._export_report("html"),
            fg_color="#4f46e5",
            hover_color="#4338ca",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_html.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        btn_csv = ctk.CTkButton(
            btn_grid,
            text="📊 Export Findings CSV",
            height=40,
            command=lambda: self._export_report("csv"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_csv.grid(row=1, column=0, padx=6, pady=6, sticky="ew")

        btn_json = ctk.CTkButton(
            btn_grid,
            text="🔍 Export Machine JSON",
            height=40,
            command=lambda: self._export_report("json"),
            fg_color="#64748b",
            hover_color="#475569",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_json.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        btn_enc = ctk.CTkButton(
            btn_grid,
            text="🔒 Export AES-256-GCM Encrypted (.phi)",
            height=40,
            command=lambda: self._export_report("encrypted"),
            fg_color="#d97706",
            hover_color="#b45309",
            font=ctk.CTkFont(family="Inter", size=12, weight="bold"),
        )
        btn_enc.grid(row=2, column=0, columnspan=2, padx=6, pady=6, sticky="ew")

        btn_grid.columnconfigure(0, weight=1)
        btn_grid.columnconfigure(1, weight=1)

    def _build_findings_table(self, parent_tab, is_db_tab: bool = False) -> None:
        """Filterable Treeview Table for Findings."""
        table_card = ctk.CTkFrame(parent_tab, fg_color="transparent")
        table_card.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # Filter bar
        filter_bar = ctk.CTkFrame(table_card, fg_color="transparent")
        filter_bar.pack(fill="x", pady=(0, 8))

        search_entry = ctk.CTkEntry(
            filter_bar,
            placeholder_text="Search findings by file, column, or masked value...",
            height=32,
            width=320,
            font=ctk.CTkFont(family="Inter", size=12),
        )
        search_entry.pack(side="left", padx=(0, 12))
        search_entry.bind("<KeyRelease>", lambda e: self._apply_table_filter(search_entry.get()))

        if is_db_tab:
            self.db_search_entry = search_entry
        else:
            self.file_search_entry = search_entry

        lbl_filter = ctk.CTkLabel(filter_bar, text="Filter Entity:", font=ctk.CTkFont(family="Inter", size=12, weight="bold"))
        lbl_filter.pack(side="left", padx=(0, 8))

        filter_menu = ctk.CTkOptionMenu(
            filter_bar,
            values=["ALL", "AADHAAR", "PAN", "GSTIN", "IN_MOBILE", "BANK_ACCOUNT", "IFSC", "VOTER_ID", "PASSPORT"],
            command=lambda val: self._apply_table_filter(search_entry.get(), entity_filter=val),
            width=140,
            height=32,
            font=ctk.CTkFont(family="Inter", size=12),
        )
        filter_menu.pack(side="left")

        # Treeview Widget Container
        tree_frame = ctk.CTkFrame(table_card, corner_radius=8, border_width=1, border_color=("#e2e8f0", "#334155"))
        tree_frame.pack(fill="both", expand=True)

        columns = ("#", "Source / File Path", "Position / Table", "Entity Type", "Masked Value", "Confidence")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)

        tree.heading("#", text="#")
        tree.heading("Source / File Path", text="Source / File Path")
        tree.heading("Position / Table", text="Position / Table")
        tree.heading("Entity Type", text="Entity Type")
        tree.heading("Masked Value", text="Masked Value")
        tree.heading("Confidence", text="Confidence")

        tree.column("#", width=40, anchor="center")
        tree.column("Source / File Path", width=340, anchor="w")
        tree.column("Position / Table", width=140, anchor="w")
        tree.column("Entity Type", width=120, anchor="center")
        tree.column("Masked Value", width=180, anchor="w")
        tree.column("Confidence", width=110, anchor="center")

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        if is_db_tab:
            self.db_tree = tree
        else:
            self.file_tree = tree

    def _build_statusbar(self) -> None:
        """Bottom Status Footer."""
        self.statusbar = ctk.CTkFrame(self, corner_radius=0, height=28, fg_color=("#f1f5f9", "#0f172a"))
        self.statusbar.pack(side="bottom", fill="x")

        self.status_label = ctk.CTkLabel(
            self.statusbar,
            text="Ready. Select a target file, directory, or SQLite database connection to scan.",
            font=ctk.CTkFont(family="Inter", size=11),
            text_color=self.colors["text_muted"],
        )
        self.status_label.pack(side="left", padx=16, pady=4)

    # -----------------------------------------------------------------------
    # Event Handlers & Actions
    # -----------------------------------------------------------------------

    def _browse_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=[("All Supported Files", "*.csv *.xlsx *.xls *.docx *.pdf *.txt *.md *.json *.jsonl *.tsv *.parquet *.db *.sqlite"), ("All Files", "*.*")],
        )
        if file_path:
            self.scan_target_path = Path(file_path)
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, file_path)

    def _browse_dir(self) -> None:
        dir_path = filedialog.askdirectory(title="Select Folder to Scan")
        if dir_path:
            self.scan_target_path = Path(dir_path)
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, dir_path)

    def _browse_db(self) -> None:
        db_path = filedialog.askopenfilename(
            title="Select SQLite Database File",
            filetypes=[("SQLite Database Files", "*.db *.sqlite *.sqlite3"), ("All Files", "*.*")],
        )
        if db_path:
            self.db_uri_val = f"sqlite:///{db_path}"
            self.db_entry.delete(0, "end")
            self.db_entry.insert(0, self.db_uri_val)

    def _start_file_scan(self) -> None:
        path_str = self.path_entry.get().strip()
        if not path_str:
            messagebox.showwarning("Input Required", "Please select or type a file or directory path first.")
            return

        target_path = Path(path_str)
        if not target_path.exists():
            messagebox.showerror("Path Not Found", f"The path does not exist:\n{target_path}")
            return

        self._run_scan_thread(is_db=False, target=target_path)

    def _start_db_scan(self) -> None:
        db_uri = self.db_entry.get().strip()
        if not db_uri:
            messagebox.showwarning("Input Required", "Please enter or select a database URI (e.g. sqlite:///data.db).")
            return

        self._run_scan_thread(is_db=True, target=db_uri)

    def _run_scan_thread(self, is_db: bool, target: Path | str) -> None:
        if self.is_scanning:
            return

        self.is_scanning = True
        self.btn_start_scan.configure(state="disabled")
        self.btn_db_scan.configure(state="disabled")

        if is_db:
            self.db_progress_bar.configure(mode="indeterminate")
            self.db_progress_bar.start()
            self.status_label.configure(text=f"Scanning database URI: {target}...")
        else:
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self.status_label.configure(text=f"Scanning target: {target}...")

        def _scan_worker():
            start_time = time.perf_counter()
            findings_list: list[Finding] = []
            try:
                if is_db:
                    scanner = self.pipeline.scan_db(str(target))
                else:
                    path_obj = Path(target)
                    if path_obj.is_dir():
                        scanner = self.engine.scan_path_parallel(path_obj)
                    else:
                        scanner = self.engine.scan_file(path_obj)

                for f in scanner:
                    findings_list.append(f)

            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Scan Error", f"An error occurred during scan:\n{exc}"))
            finally:
                duration = time.perf_counter() - start_time
                self.after(0, lambda: self._on_scan_complete(findings_list, duration, is_db=is_db))

        threading.Thread(target=_scan_worker, daemon=True).start()

    def _on_scan_complete(self, findings: list[Finding], duration: float, is_db: bool) -> None:
        self.is_scanning = False
        self.findings = findings

        self.progress_bar.stop()
        self.progress_bar.set(1.0)
        self.db_progress_bar.stop()
        self.db_progress_bar.set(1.0)

        self.btn_start_scan.configure(state="normal")
        self.btn_db_scan.configure(state="normal")

        # Update Metrics
        total_count = len(findings)
        high_count = sum(1 for f in findings if f.confidence == "HIGH")
        unique_sources = len({str(f.location.file_path) for f in findings})

        if high_count > 0:
            status_text = "CRITICAL RISK"
            status_color = self.colors["accent_rose"]
        elif total_count > 0:
            status_text = "WARNING"
            status_color = self.colors["accent_amber"]
        else:
            status_text = "PASS — LOW RISK"
            status_color = self.colors["accent_emerald"]

        self.metric_cards["Total Findings"].configure(text=str(total_count))
        self.metric_cards["High Risk Exposures"].configure(text=str(high_count))
        self.metric_cards["Sources Affected"].configure(text=str(unique_sources))
        self.metric_cards["Compliance Status"].configure(text=status_text, text_color=status_color)

        self.status_label.configure(
            text=f"Scan completed in {duration:.2f}s. {total_count} finding(s) detected across {unique_sources} source(s)."
        )

        # Populate tables
        self._populate_table(self.file_tree, findings)
        self._populate_table(self.db_tree, findings)

    def _populate_table(self, tree: ttk.Treeview, findings: list[Finding]) -> None:
        for item in tree.get_children():
            tree.delete(item)

        for idx, f in enumerate(findings, start=1):
            loc = f.location.as_dict()
            file_name = str(loc["file"])
            sheet_str = f" ({loc['sheet']})" if loc.get("sheet") else ""
            col_str = f"Col {loc['column']}" if loc.get("column") else ""
            pos_str = f"Row {loc['row']} {col_str}{sheet_str}".strip()

            tree.insert(
                "",
                "end",
                values=(idx, file_name, pos_str, f.entity_type, f.masked_value, f.confidence),
            )

    def _apply_table_filter(self, search_text: str = "", entity_filter: str = "ALL") -> None:
        search_lower = search_text.lower()
        active_tree = self.file_tree if self.tabview.get() == " File & Folder Scan " else self.db_tree

        filtered = []
        for f in self.findings:
            loc = f.location.as_dict()
            text_haystack = f"{loc['file']} {loc.get('sheet','')} {loc.get('column','')} {f.entity_type} {f.masked_value}".lower()

            matches_search = not search_lower or (search_lower in text_haystack)
            matches_entity = (entity_filter == "ALL" or f.entity_type == entity_filter)

            if matches_search and matches_entity:
                filtered.append(f)

        self._populate_table(active_tree, filtered)

    def _execute_remediation(self) -> None:
        path_str = self.path_entry.get().strip()
        if not path_str:
            messagebox.showwarning("Input Required", "Please select a target file to remediate.")
            return

        target_path = Path(path_str)
        if not target_path.is_file():
            messagebox.showwarning("File Required", "Remediation requires a single file target.")
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Remediated File As",
            defaultextension=target_path.suffix,
            initialfile=f"{target_path.stem}_remediated{target_path.suffix}",
        )
        if not output_path:
            return

        mode_selection = self.rem_mode_seg.get()
        if "Redact" in mode_selection:
            mode = "redact"
        elif "Tokenize" in mode_selection:
            mode = "tokenize"
        else:
            mode = "mask"

        try:
            count = redact_file(target_path, Path(output_path), mode=mode)
            messagebox.showinfo(
                "Remediation Successful",
                f"Sanitized file created at:\n{output_path}\n\nTotal cells remediated: {count} using {mode.upper()} mode.",
            )
        except Exception as exc:
            messagebox.showerror("Remediation Error", f"Failed to remediate file:\n{exc}")

    def _export_report(self, fmt: str) -> None:
        if not self.findings:
            messagebox.showwarning("No Findings", "There are no findings to export. Please run a scan first.")
            return

        ext_map = {"pdf": ".pdf", "html": ".html", "csv": ".csv", "json": ".json", "encrypted": ".phi"}
        file_path = filedialog.asksaveasfilename(
            title=f"Save {fmt.upper()} Audit Report",
            defaultextension=ext_map.get(fmt, ".csv"),
            initialfile=f"compliance_report_{int(time.time())}{ext_map.get(fmt, '.csv')}",
        )
        if not file_path:
            return

        out_path = Path(file_path)
        try:
            if fmt == "pdf":
                write_pdf_summary(self.findings, out_path, target_path_str=str(self.scan_target_path or "Workspace"))
            elif fmt == "html":
                write_html(self.findings, out_path, target_path_str=str(self.scan_target_path or "Workspace"))
            elif fmt == "json":
                write_json(self.findings, out_path)
            elif fmt == "encrypted":
                passphrase = ctk.CTkInputDialog(text="Enter passphrase for AES-256-GCM encryption:", title="Passphrase Required").get_input()
                if not passphrase:
                    return
                write_encrypted(self.findings, out_path, passphrase=passphrase)
            else:
                write_csv(self.findings, out_path)

            messagebox.showinfo("Export Complete", f"Compliance audit report successfully saved to:\n{out_path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", f"Could not generate report:\n{exc}")


def launch_gui() -> None:
    """Launch the CustomTkinter Compliance Scanner Desktop GUI."""
    app = ComplianceScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()

"""
Modern GUI for ExoWin
Using CustomTkinter for a modern, responsive UI
"""
import os
import sys
import threading
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
import datetime

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
from PIL import Image, ImageDraw, ImageTk
import math
import os
import sys
import threading
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
import datetime

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
from PIL import Image, ImageDraw, ImageTk

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pefile
from exowin.analyzer import ExoWinAnalyzer
from exowin.extractors import MLFeaturesExtractor, DLLFeaturesExtractor
from exowin.reporters import JSONReporter, HTMLReporter, MarkdownReporter, CSVReporter

# Set appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def create_app_icon(size=64):
    """Create a programmatic app icon with hexagon shape"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center = size // 2
    radius = size // 2 - 4

    # Draw hexagon layers
    colors = [(59, 142, 208, 255), (47, 165, 114, 255), (31, 106, 165, 255)]
    for i, color in enumerate(colors):
        r = radius - (i * 8)
        if r > 0:
            points = [(center + r * math.cos(math.pi / 3 * j - math.pi / 2),
                       center + r * math.sin(math.pi / 3 * j - math.pi / 2)) for j in range(6)]
            draw.polygon(points, fill=color)

    # Draw "EX" text
    line_width = max(2, size // 20)
    ex_size = size // 3
    start_x, start_y = center - ex_size // 2 - 2, center - ex_size // 2
    white = (255, 255, 255, 255)

    # E shape
    draw.line([(start_x, start_y), (start_x, start_y + ex_size)], fill=white, width=line_width)
    draw.line([(start_x, start_y), (start_x + ex_size//2, start_y)], fill=white, width=line_width)
    draw.line([(start_x, start_y + ex_size//2), (start_x + ex_size//3, start_y + ex_size//2)], fill=white, width=line_width)
    draw.line([(start_x, start_y + ex_size), (start_x + ex_size//2, start_y + ex_size)], fill=white, width=line_width)

    # X shape
    x_start = center + 2
    draw.line([(x_start, start_y), (x_start + ex_size//2, start_y + ex_size)], fill=white, width=line_width)
    draw.line([(x_start + ex_size//2, start_y), (x_start, start_y + ex_size)], fill=white, width=line_width)

    return img


def create_sidebar_logo(size=40):
    """Create a smaller logo icon for sidebar"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    center = size // 2
    radius = size // 2 - 2

    # Outer hexagon (blue)
    points = [(center + radius * math.cos(math.pi / 3 * j - math.pi / 2),
               center + radius * math.sin(math.pi / 3 * j - math.pi / 2)) for j in range(6)]
    draw.polygon(points, fill=(59, 142, 208, 255))

    # Inner hexagon (green)
    inner_r = radius - 6
    points_inner = [(center + inner_r * math.cos(math.pi / 3 * j - math.pi / 2),
                     center + inner_r * math.sin(math.pi / 3 * j - math.pi / 2)) for j in range(6)]
    draw.polygon(points_inner, fill=(47, 165, 114, 255))

    return img

class StatCard(ctk.CTkFrame):
    """Stat card for dashboard"""

    def __init__(self, master, title: str, value: str = "0", color: str = "blue", **kwargs):
        super().__init__(master, corner_radius=15, fg_color=("gray90", "gray20"), **kwargs)

        self.grid_columnconfigure(0, weight=1)

        colors = {
            "blue": ("#3B8ED0", "#1F6AA5"),
            "green": ("#2FA572", "#2FA572"),
            "orange": ("#F5A623", "#D4850E"),
            "red": ("#E74C3C", "#C0392B"),
            "purple": ("#9B59B6", "#8E44AD"),
        }

        accent = colors.get(color, colors["blue"])

        # Value (big number)
        self.value_label = ctk.CTkLabel(
            self, text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=accent[0] if ctk.get_appearance_mode() == "Light" else accent[1]
        )
        self.value_label.grid(row=0, column=0, padx=20, pady=(15, 5))

        # Title
        self.title_label = ctk.CTkLabel(
            self, text=title,
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70")
        )
        self.title_label.grid(row=1, column=0, padx=20, pady=(0, 15))

    def set_value(self, value: str):
        self.value_label.configure(text=value)

class PEAnalyzerGUI(ctk.CTk):
    """ExoWin - Modern GUI"""

    def __init__(self):
        super().__init__()

        # Window setup
        self.title("ExoWin")
        self.geometry("1400x900")
        self.minsize(1000, 700)

        # Set window icon
        try:
            icon_img = create_app_icon(64)
            self._icon_photo = ImageTk.PhotoImage(icon_img)
            self.iconphoto(True, self._icon_photo)
        except Exception as e:
            print(f"Could not set icon: {e}")

        # Make responsive
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Initialize components
        self.analyzer = ExoWinAnalyzer()
        self.ml_extractor = MLFeaturesExtractor()
        self.dll_extractor = DLLFeaturesExtractor()
        self.reporters = {
            "JSON": JSONReporter(),
            "HTML": HTMLReporter(),
            "Markdown": MarkdownReporter(),
            "CSV": CSVReporter(),
        }

        # State
        self.current_file: Optional[str] = None
        self.current_folder: Optional[str] = None  # Current selected folder
        self.current_results: Optional[Dict] = None
        self.batch_results: List[Dict] = []
        self.collapsed_sections: Dict[str, bool] = {}  # Track collapsed state
        self.expanded_batch_rows: Dict[int, bool] = {}  # Track expanded batch rows

        # Build UI
        self._create_sidebar()
        self._create_main_content()

        # Set default view
        self.show_home()

    def _create_sidebar(self):
        """Create sidebar navigation"""
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=("gray95", "gray10"))
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        # Logo Image
        try:
            logo_img = create_sidebar_logo(40)
            self._sidebar_logo = ctk.CTkImage(light_image=logo_img, dark_image=logo_img, size=(40, 40))
            self.logo_image = ctk.CTkLabel(self.sidebar, image=self._sidebar_logo, text="")
            self.logo_image.grid(row=0, column=0, padx=20, pady=(20, 5))
        except Exception as e:
            print(f"Could not load logo: {e}")

        # Logo/Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar, text="ExoWin",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.logo_label.grid(row=1, column=0, padx=20, pady=(5, 2))

        self.subtitle = ctk.CTkLabel(
            self.sidebar, text="ExoWin GUI",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray60")
        )
        self.subtitle.grid(row=2, column=0, padx=20, pady=(0, 20))

        # Navigation buttons
        self.nav_buttons = {}

        nav_items = [
            ("home", "Home", self.show_home),
            ("analyze", "Analysis", self.show_analysis),
            ("batch", "Batch", self.show_batch),
            ("log", "Log", self.show_log),
        ]

        for i, (key, text, command) in enumerate(nav_items):
            btn = ctk.CTkButton(
                self.sidebar, text=text, anchor="w",
                font=ctk.CTkFont(size=14),
                fg_color="transparent",
                text_color=("gray20", "gray90"),
                hover_color=("gray80", "gray25"),
                height=45, corner_radius=10,
                command=command
            )
            btn.grid(row=i + 3, column=0, padx=15, pady=3, sticky="ew")
            self.nav_buttons[key] = btn

        # Spacer
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.grid(row=11, column=0, sticky="nsew")

        # Theme toggle
        self.theme_switch = ctk.CTkSwitch(
            self.sidebar, text="Dark Mode",
            command=self._toggle_theme,
            font=ctk.CTkFont(size=12)
        )
        self.theme_switch.grid(row=12, column=0, padx=20, pady=10)
        self.theme_switch.select()  # Dark mode default

        # Version
        self.version_label = ctk.CTkLabel(
            self.sidebar, text="v1.1.0",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60")
        )
        self.version_label.grid(row=13, column=0, padx=20, pady=(5, 20))

    def _create_main_content(self):
        """Create main content area"""
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

        # Top bar with file info and actions
        self._create_topbar()

        # Content frames
        self.content_frames = {}
        self._create_home_frame()
        self._create_analysis_frame()
        self._create_batch_frame()
        self._create_log_frame()

    def _create_topbar(self):
        """Create top action bar"""
        self.topbar = ctk.CTkFrame(self.main_container, height=60, corner_radius=15)
        self.topbar.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.topbar.grid_columnconfigure(1, weight=1)

        # File info
        self.file_icon = ctk.CTkLabel(self.topbar, text="[F]", font=ctk.CTkFont(size=16, weight="bold"))
        self.file_icon.grid(row=0, column=0, padx=(15, 5), pady=15)

        self.file_label = ctk.CTkLabel(
            self.topbar, text="No file selected",
            font=ctk.CTkFont(size=13)
        )
        self.file_label.grid(row=0, column=1, sticky="w", padx=5)

        # Action buttons
        self.btn_open = ctk.CTkButton(
            self.topbar, text="Open File", width=120,
            command=self._open_file, corner_radius=8
        )
        self.btn_open.grid(row=0, column=2, padx=5, pady=10)


        # Recursive checkbox
        self.recursive_var = ctk.BooleanVar(value=False)
        self.btn_folder = ctk.CTkButton(
            self.topbar, text="Open Folder", width=130,
            command=self._open_folder, corner_radius=8,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40")
        )
        self.btn_folder.grid(row=0, column=3, padx=(5,0), pady=10, sticky="w")
        self.recursive_cb = ctk.CTkCheckBox(
            self.topbar, text="Recursive", variable=self.recursive_var)
        self.recursive_cb.grid(row=0, column=3, padx=(140,5), pady=10, sticky="w")

        self.btn_export = ctk.CTkButton(
            self.topbar, text="Export", width=100,
            command=self._export_results, corner_radius=8,
            fg_color=("#2FA572", "#2FA572"),
            hover_color=("#248A5C", "#248A5C")
        )
        self.btn_export.grid(row=0, column=4, padx=(5, 15), pady=10)

    def _create_home_frame(self):
        """Create home/dashboard frame"""
        frame = ctk.CTkFrame(self.main_container, corner_radius=15, fg_color="transparent")
        self.content_frames["home"] = frame

        frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        # Welcome header
        welcome = ctk.CTkLabel(
            frame, text="Welcome to ExoWin",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        welcome.grid(row=0, column=0, columnspan=5, pady=(0, 5), sticky="w")

        desc = ctk.CTkLabel(
            frame,
            text="Analyze PE files and extract features for Machine Learning",
            font=ctk.CTkFont(size=14),
            text_color=("gray50", "gray60")
        )
        desc.grid(row=1, column=0, columnspan=5, pady=(0, 30), sticky="w")

        # Stat cards
        self.stat_cards = {}

        stats = [
            ("features", "ML Features", "181", "blue"),
            ("sections", "Sections", "0", "green"),
            ("imports", "Imports", "0", "orange"),
            ("exports", "Exports", "0", "purple"),
            ("suspicious", "Suspicious", "0", "red"),
        ]

        for i, (key, title, value, color) in enumerate(stats):
            card = StatCard(frame, title, value, color)
            card.grid(row=2, column=i, padx=10, pady=10, sticky="nsew")
            self.stat_cards[key] = card

        # Quick actions
        actions_label = ctk.CTkLabel(
            frame, text="Quick Actions",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        actions_label.grid(row=3, column=0, columnspan=5, pady=(30, 15), sticky="w")

        # Action cards
        actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
        actions_frame.grid(row=4, column=0, columnspan=5, sticky="ew")
        actions_frame.grid_columnconfigure((0, 1), weight=1)

        action_items = [
            ("A", "Full Analysis", "Analyze PE headers, sections, imports", self._smart_analyze),
            ("B", "Batch Extraction", "Extract features from multiple files", self._smart_batch),
        ]

        for i, (icon, title, desc, cmd) in enumerate(action_items):
            card = ctk.CTkFrame(actions_frame, corner_radius=15)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            card.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=36)).grid(row=0, column=0, pady=(20, 10))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=16, weight="bold")).grid(row=1, column=0, pady=5)
            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=12), text_color=("gray50", "gray60"), wraplength=180).grid(row=2, column=0, pady=5)
            ctk.CTkButton(card, text="Start", width=100, corner_radius=8, command=cmd).grid(row=3, column=0, pady=(10, 20))

    def _create_analysis_frame(self):
        """Create analysis results frame"""
        frame = ctk.CTkFrame(self.main_container, corner_radius=15, fg_color="transparent")
        self.content_frames["analyze"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))

        ctk.CTkLabel(header, text="Analysis Results", font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")

        ctk.CTkButton(
            header, text="Analyze", width=110,
            command=self._run_full_analysis, corner_radius=8
        ).pack(side="right", padx=5)

        # Left panel - Tree view
        left_panel = ctk.CTkFrame(frame, corner_radius=15)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        left_panel.grid_rowconfigure(1, weight=1)
        left_panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left_panel, text="Structure", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=15, pady=10, sticky="w")

        self.analysis_tree_frame = ctk.CTkScrollableFrame(left_panel, corner_radius=10)
        self.analysis_tree_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.analysis_tree_frame.grid_columnconfigure(0, weight=1)

        # Right panel - Details
        right_panel = ctk.CTkFrame(frame, corner_radius=15)
        right_panel.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right_panel, text="Details", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=15, pady=10, sticky="w")

        self.analysis_details_frame = ctk.CTkScrollableFrame(right_panel, corner_radius=10)
        self.analysis_details_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.analysis_details_frame.grid_columnconfigure(0, weight=1)

    def _create_batch_frame(self):
        """Create batch feature extraction frame"""
        frame = ctk.CTkFrame(self.main_container, corner_radius=15, fg_color="transparent")
        self.content_frames["batch"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        ctk.CTkLabel(header, text="Feature Extraction", font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text="(Extract ML features from file/folder)", font=ctk.CTkFont(size=12), text_color=("gray50", "gray60")).pack(side="left", padx=15)

        # Options panel
        settings = ctk.CTkFrame(frame, corner_radius=15)
        settings.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        options_frame = ctk.CTkFrame(settings, fg_color="transparent")
        options_frame.pack(fill="x", padx=15, pady=15)

        ctk.CTkLabel(options_frame, text="Pattern:").pack(side="left")
        self.batch_pattern_entry = ctk.CTkEntry(options_frame, width=140, placeholder_text="*.exe,*.dll")
        self.batch_pattern_entry.pack(side="left", padx=(5, 20))
        self.batch_pattern_entry.insert(0, "*.exe,*.dll")

        ctk.CTkLabel(options_frame, text="Label:").pack(side="left")
        self.batch_label_entry = ctk.CTkEntry(options_frame, width=150, placeholder_text="e.g., malware/benign")
        self.batch_label_entry.pack(side="left", padx=(5, 20))


        ctk.CTkButton(
            options_frame, text="Extract Features", width=140,
            command=self._run_batch_extraction, corner_radius=8,
            fg_color=("#2FA572", "#2FA572"), hover_color=("#248A5C", "#248A5C")
        ).pack(side="right")

        # Progress
        progress_frame = ctk.CTkFrame(settings, corner_radius=10, fg_color=("gray90", "gray17"))
        progress_frame.pack(fill="x", padx=15, pady=(0, 15))
        progress_frame.grid_columnconfigure(0, weight=1)

        self.batch_progress = ctk.CTkProgressBar(progress_frame, height=12, corner_radius=6)
        self.batch_progress.pack(fill="x", padx=15, pady=(15, 8))
        self.batch_progress.set(0)

        self.batch_status = ctk.CTkLabel(progress_frame, text="Ready - select a file or folder first", font=ctk.CTkFont(size=12))
        self.batch_status.pack(anchor="w", padx=15, pady=(0, 12))

        # Results
        results_frame = ctk.CTkFrame(frame, corner_radius=15)
        results_frame.grid(row=2, column=0, sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)

        results_header = ctk.CTkFrame(results_frame, fg_color="transparent")
        results_header.grid(row=0, column=0, sticky="ew", padx=15, pady=10)

        ctk.CTkLabel(results_header, text="Results (click to view features)", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        ctk.CTkButton(
            results_header, text="Export CSV", width=120,
            command=self._export_batch_csv, corner_radius=8
        ).pack(side="right")

        self.batch_results_scroll = ctk.CTkScrollableFrame(results_frame, corner_radius=10)
        self.batch_results_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.batch_results_scroll.grid_columnconfigure(0, weight=1)

    def _create_log_frame(self):
        """Create log frame"""
        frame = ctk.CTkFrame(self.main_container, corner_radius=15, fg_color="transparent")
        self.content_frames["log"] = frame

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        ctk.CTkLabel(header, text="Activity Log", font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="Clear", width=80, command=self._clear_log, corner_radius=8).pack(side="right")

        # Log text
        log_container = ctk.CTkFrame(frame, corner_radius=15)
        log_container.grid(row=1, column=0, sticky="nsew")
        log_container.grid_columnconfigure(0, weight=1)
        log_container.grid_rowconfigure(0, weight=1)

        self.log_text = ctk.CTkTextbox(log_container, corner_radius=10, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    # === Navigation ===

    def _select_nav(self, key: str):
        """Update navigation button states"""
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")

    def _show_frame(self, key: str):
        """Show a content frame"""
        for k, frame in self.content_frames.items():
            if k == key:
                frame.grid(row=1, column=0, sticky="nsew")
            else:
                frame.grid_forget()
        self._select_nav(key)

    def show_home(self):
        self._show_frame("home")

    def show_analysis(self):
        self._show_frame("analyze")

    def show_batch(self):
        self._show_frame("batch")

    def show_log(self):
        self._show_frame("log")

    # === Actions ===

    def _toggle_theme(self):
        """Toggle dark/light theme"""
        if self.theme_switch.get():
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def _open_file(self):
        """Open a PE file"""
        filetypes = [
            ("PE Files", "*.exe *.dll *.sys *.ocx *.scr"),
            ("All Files", "*.*")
        ]
        filepath = filedialog.askopenfilename(title="Select PE File", filetypes=filetypes)

        if filepath:
            self.current_file = filepath
            self.current_folder = None  # Clear folder selection
            self.file_icon.configure(text="[F]")
            self.file_label.configure(text=Path(filepath).name)
            self._log(f"Opened: {filepath}")

    def _open_folder(self):
        """Open folder containing PE files"""
        folder = filedialog.askdirectory(title="Select Folder")
        if folder:
            self.current_folder = folder
            self.current_file = None  # Clear single file selection
            folder_name = Path(folder).name
            # Count PE files in folder
            pe_count = len(list(Path(folder).glob("*.exe"))) + len(list(Path(folder).glob("*.dll")))
            self.file_icon.configure(text="[D]")
            self.file_label.configure(text=f"{folder_name}/ ({pe_count} PE files)")
            self._log(f"Selected folder: {folder} ({pe_count} PE files)")

    def _smart_analyze(self):
        """Smart analyze: run if file/folder selected, else go to Analysis tab"""
        if self.current_file or self.current_folder:
            self._run_full_analysis()
        else:
            self.show_analysis()

    def _smart_batch(self):
        """Smart batch: run extraction if file/folder selected, else go to Batch tab"""
        if self.current_file or self.current_folder:
            self.show_batch()
            self._run_batch_extraction()
        else:
            self.show_batch()

    def _run_full_analysis(self):
        """Run full analysis on file or folder"""
        if self.current_folder:
            # Analyze folder
            self._scan_folder_analysis()
        elif self.current_file:
            # Analyze single file
            self._log(f"Starting analysis: {Path(self.current_file).name}")
            threading.Thread(target=self._do_full_analysis, daemon=True).start()
        else:
            messagebox.showwarning("No Selection", "Please open a PE file or folder first.")

    def _scan_folder_analysis(self):
        """Scan folder for PE files and analyze them"""
        if not self.current_folder:
            messagebox.showwarning("No Folder", "Please select a folder using 'Open Folder' button first.")
            return

        recursive = self.folder_recursive_var.get()
        self._log(f"Scanning folder: {self.current_folder} (recursive={recursive})")
        threading.Thread(target=self._do_folder_analysis, args=(recursive,), daemon=True).start()

    def _do_folder_analysis(self, recursive=False):
        """Perform folder analysis in thread"""
        folder_path = Path(self.current_folder)
        patterns = ["*.exe", "*.dll", "*.sys", "*.ocx", "*.scr"]
        pe_files = []
        for pattern in patterns:
            if recursive:
                pe_files.extend(folder_path.rglob(pattern))
            else:
                pe_files.extend(folder_path.glob(pattern))

        if not pe_files:
            self._log("No PE files found in folder")
            self.after(0, lambda: messagebox.showinfo("No Files", "No PE files found in the selected folder."))
            return

        self._log(f"Found {len(pe_files)} PE files")

        all_results = []
        total_sections = 0
        total_imports = 0
        total_suspicious = 0

        for i, filepath in enumerate(pe_files):
            try:
                result = self.analyzer.analyze_file(str(filepath))
                result["_filepath"] = str(filepath)
                all_results.append(result)

                total_sections += result.get("sections", {}).get("count", 0)
                total_imports += len(result.get("imports", {}).get("imports", []))
                total_suspicious += len(result.get("suspicious_indicators", []))

                self._log(f"Analyzed: {filepath.name}")
            except Exception as e:
                self._log(f"Failed: {filepath.name} - {e}")

        if all_results:
            self.current_results = all_results
            self.after(0, lambda: self._display_folder_analysis(all_results, total_sections, total_imports, total_suspicious))
            self._log(f"Folder analysis complete: {len(all_results)} files")

    def _do_full_analysis(self):
        """Perform full analysis in thread"""
        try:
            result = self.analyzer.analyze_file(self.current_file)
            self.current_results = result

            # Update UI on main thread
            self.after(0, lambda: self._display_analysis(result))
            self._log("Analysis complete")

        except Exception as e:
            self._log(f"Error: {e}")
            self.after(0, lambda: messagebox.showerror("Error", str(e)))

    def _display_analysis(self, result: Dict):
        """Display analysis results with collapsible sections"""
        # Update stat cards
        sections = result.get("sections", {})
        imports = result.get("imports", {})
        indicators = result.get("suspicious_indicators", [])
        dll_features = result.get("dll_features", {})

        self.stat_cards["sections"].set_value(str(sections.get("count", 0)))
        self.stat_cards["imports"].set_value(str(len(imports.get("imports", []))))
        self.stat_cards["suspicious"].set_value(str(len(indicators)))

        # Update exports stat
        exports_count = dll_features.get("exports", {}).get("count", 0) if dll_features else imports.get("exports", {}).get("count", 0)
        self.stat_cards["exports"].set_value(str(exports_count))

        # Store result for toggle
        self._current_analysis_result = result

        # Build structure tree with collapsible sections
        self._build_structure_tree(result)

        # Build formatted details
        self._build_details_view(result)

        self.show_analysis()

    def _build_structure_tree(self, result: Dict):
        """Build collapsible structure tree"""
        for widget in self.analysis_tree_frame.winfo_children():
            widget.destroy()

        file_info = result.get("file_info", {})
        sections = result.get("sections", {})
        imports = result.get("imports", {})
        indicators = result.get("suspicious_indicators", [])
        headers = result.get("headers", {})
        strings = result.get("strings", {})

        row = 0

        # File Info Section
        row = self._add_collapsible_section(
            row, "file_info", "File Info", "#3498DB",
            self._build_file_info_content, file_info
        )

        # PE Headers Section
        row = self._add_collapsible_section(
            row, "headers", "PE Headers", "#9B59B6",
            self._build_headers_content, headers
        )

        # Security Features Section (for both EXE and DLL)
        opt_header = headers.get("optional_header", {})
        row = self._add_collapsible_section(
            row, "security", "Security Features", "#16A085",
            self._build_security_content, opt_header
        )

        # Sections Section
        row = self._add_collapsible_section(
            row, "sections", f"Sections ({sections.get('count', 0)})", "#27AE60",
            self._build_sections_content, sections
        )

        # Imports Section
        import_count = len(imports.get("imports", []))
        func_count = sum(len(imp.get("functions", [])) for imp in imports.get("imports", []))
        row = self._add_collapsible_section(
            row, "imports", f"Imports ({import_count} DLLs, {func_count} funcs)", "#F39C12",
            self._build_imports_content, imports
        )

        # Strings Section
        if strings:
            string_count = strings.get("count", 0)
            row = self._add_collapsible_section(
                row, "strings", f"Strings ({string_count})", "#1ABC9C",
                self._build_strings_content, strings
            )

        # Suspicious Indicators Section
        if indicators:
            row = self._add_collapsible_section(
                row, "suspicious", f"Suspicious ({len(indicators)})", "#E74C3C",
                self._build_suspicious_content, indicators
            )

        # DLL Features Section (if DLL)
        dll_features = result.get("dll_features", {})
        if dll_features and dll_features.get("is_dll"):
            row = self._add_collapsible_section(
                row, "dll_features", "DLL Analysis", "#8E44AD",
                self._build_dll_features_content, dll_features
            )

    def _add_collapsible_section(self, row: int, section_id: str, title: str, color: str, content_builder, data) -> int:
        """Add a collapsible section to the tree"""
        is_collapsed = self.collapsed_sections.get(section_id, False)  # Default expanded

        # Section header - use light/dark bg colors instead of hex with alpha
        light_bg = "gray90"
        dark_bg = "gray25"
        header_frame = ctk.CTkFrame(self.analysis_tree_frame, corner_radius=8, fg_color=(light_bg, dark_bg), height=38)
        header_frame.grid(row=row, column=0, sticky="ew", pady=3, padx=2)
        header_frame.grid_columnconfigure(1, weight=1)

        toggle_text = "▶" if is_collapsed else "▼"
        toggle_btn = ctk.CTkButton(
            header_frame, text=toggle_text, width=28, height=28,
            fg_color="transparent", hover_color=("gray80", "gray35"),
            text_color=color, font=ctk.CTkFont(size=12),
            command=lambda sid=section_id: self._toggle_section(sid)
        )
        toggle_btn.grid(row=0, column=0, padx=5, pady=5)

        ctk.CTkLabel(header_frame, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color=color).grid(row=0, column=1, sticky="w", pady=5)
        row += 1

        # Section content
        if not is_collapsed:
            content_frame = ctk.CTkFrame(self.analysis_tree_frame, corner_radius=6, fg_color=("gray95", "gray17"))
            content_frame.grid(row=row, column=0, sticky="ew", pady=(0, 5), padx=8)
            content_frame.grid_columnconfigure(0, weight=1)
            content_builder(content_frame, data)
            row += 1

        return row

    def _toggle_section(self, section_id: str):
        """Toggle a section's collapsed state"""
        self.collapsed_sections[section_id] = not self.collapsed_sections.get(section_id, False)
        if hasattr(self, '_current_analysis_result'):
            self._build_structure_tree(self._current_analysis_result)

    def _build_file_info_content(self, frame: ctk.CTkFrame, file_info: Dict):
        """Build file info section content"""
        frame.grid_columnconfigure(1, weight=1)
        sha256 = file_info.get("sha256", "N/A")
        sha256_display = sha256[:40] + "..." if sha256 and len(sha256) > 40 else sha256
        ssdeep = file_info.get("ssdeep", "")
        ssdeep_display = ssdeep[:35] + "..." if ssdeep and len(ssdeep) > 35 else ssdeep
        items = [
            ("Filename", file_info.get("filename", "N/A")),
            ("Size", f"{file_info.get('size', 0):,} bytes"),
            ("MD5", file_info.get("md5", "N/A")),
            ("SHA1", file_info.get("sha1", "N/A")),
            ("SHA256", sha256_display),
            ("Entropy", f"{file_info.get('entropy', 0):.4f} - {file_info.get('entropy_interpretation', '')}"),
            ("Imphash", file_info.get("imphash", "N/A")),
        ]
        if ssdeep_display:
            items.append(("SSDeep", ssdeep_display))
        for i, (label, value) in enumerate(items):
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11), text_color=("#3498DB", "#5DADE2")).grid(row=i, column=0, sticky="w", padx=10, pady=3)
            ctk.CTkLabel(frame, text=str(value), font=ctk.CTkFont(size=11, family="Consolas")).grid(row=i, column=1, sticky="w", padx=5, pady=3)

    def _build_headers_content(self, frame: ctk.CTkFrame, headers: Dict):
        """Build PE headers section content"""
        frame.grid_columnconfigure(1, weight=1)
        file_hdr = headers.get("file_header", {})
        opt = headers.get("optional_header", {})

        # Handle entry point - might be string or int
        entry_point = opt.get('AddressOfEntryPoint', 0)
        if isinstance(entry_point, str):
            entry_str = entry_point
        else:
            entry_str = f"0x{entry_point:08X}"

        # Handle image base - might be string or int
        image_base = opt.get('ImageBase', 0)
        if isinstance(image_base, str):
            base_str = image_base
        else:
            base_str = f"0x{image_base:X}"

        # Get characteristics list
        chars = file_hdr.get("Characteristics", [])
        chars_str = ", ".join(chars[:4]) if isinstance(chars, list) else str(chars)
        if isinstance(chars, list) and len(chars) > 4:
            chars_str += f" (+{len(chars)-4})"

        items = [
            ("PE Type", headers.get("pe_type", "Unknown")),
            ("Machine", file_hdr.get("Machine", "N/A")),
            ("Subsystem", opt.get("Subsystem", "N/A")),
            ("Entry Point", entry_str),
            ("Image Base", base_str),
            ("Linker", f"{opt.get('MajorLinkerVersion', 0)}.{opt.get('MinorLinkerVersion', 0)}"),
            ("Timestamp", file_hdr.get("TimeDateStamp", "N/A")),
            ("Sections", file_hdr.get("NumberOfSections", 0)),
            ("Checksum", opt.get("CheckSum", "N/A")),
            ("Flags", chars_str),
        ]
        for i, (label, value) in enumerate(items):
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11), text_color=("#9B59B6", "#BB8FCE")).grid(row=i, column=0, sticky="w", padx=10, pady=3)
            ctk.CTkLabel(frame, text=str(value), font=ctk.CTkFont(size=11, family="Consolas")).grid(row=i, column=1, sticky="w", padx=5, pady=3)

    def _build_security_content(self, frame: ctk.CTkFrame, opt_header: Dict):
        """Build security features content from DllCharacteristics"""
        frame.grid_columnconfigure(1, weight=1)

        dll_char = opt_header.get("DllCharacteristics", "0x0")

        # Parse hex value
        try:
            if isinstance(dll_char, str):
                char_value = int(dll_char, 16)
            else:
                char_value = int(dll_char)
        except (ValueError, TypeError):
            char_value = 0

        # Define security features with their flags
        features = [
            (0x0040, "ASLR", "Address Space Layout Randomization"),
            (0x0100, "DEP/NX", "Data Execution Prevention"),
            (0x4000, "CFG", "Control Flow Guard"),
            (0x0020, "High Entropy VA", "64-bit ASLR with high entropy"),
            (0x0080, "Force Integrity", "Code signing required"),
            (0x0400, "No SEH", "No structured exception handling"),
        ]

        # Calculate security score
        score = 0
        if char_value & 0x0040: score += 25  # ASLR
        if char_value & 0x0100: score += 25  # DEP
        if char_value & 0x4000: score += 25  # CFG
        if char_value & 0x0020: score += 15  # High Entropy
        if char_value & 0x0080: score += 10  # Force Integrity

        # Score color
        if score >= 75:
            score_color = "#27AE60"
        elif score >= 50:
            score_color = "#F39C12"
        else:
            score_color = "#E74C3C"

        # Security score row
        ctk.CTkLabel(frame, text="Security Score", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=("#16A085", "#1ABC9C")).grid(row=0, column=0, sticky="w", padx=10, pady=3)
        ctk.CTkLabel(frame, text=f"{score}/100", font=ctk.CTkFont(size=11, family="Consolas", weight="bold"),
                     text_color=score_color).grid(row=0, column=1, sticky="w", padx=5, pady=3)

        # Feature rows
        for i, (flag, name, desc) in enumerate(features, start=1):
            enabled = bool(char_value & flag)
            status = "✓ Enabled" if enabled else "✗ Disabled"
            status_color = "#27AE60" if enabled else "#E74C3C"

            # Important features (ASLR, DEP, CFG) show red if disabled
            if not enabled and flag in [0x0040, 0x0100, 0x4000]:
                status_color = "#E74C3C"
            elif not enabled:
                status_color = ("gray50", "gray60")

            ctk.CTkLabel(frame, text=name, font=ctk.CTkFont(size=10),
                         text_color=("#16A085", "#1ABC9C")).grid(row=i, column=0, sticky="w", padx=10, pady=2)
            ctk.CTkLabel(frame, text=status, font=ctk.CTkFont(size=10, family="Consolas"),
                         text_color=status_color).grid(row=i, column=1, sticky="w", padx=5, pady=2)

    def _build_sections_content(self, frame: ctk.CTkFrame, sections: Dict):
        """Build sections content with table"""
        frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        # Header
        headers = ["Name", "VSize", "Entropy", "Characteristics"]
        for i, h in enumerate(headers):
            ctk.CTkLabel(frame, text=h, font=ctk.CTkFont(size=10, weight="bold"), text_color=("#27AE60", "#2ECC71")).grid(row=0, column=i, padx=8, pady=5, sticky="w")

        for i, sec in enumerate(sections.get("sections", [])[:12], start=1):
            entropy = sec.get("Entropy", 0)
            # Color based on entropy
            if entropy > 7.2:
                entropy_color = "#E74C3C"  # High - suspicious
            elif entropy > 6.5:
                entropy_color = "#F39C12"  # Medium - warning
            else:
                entropy_color = ("gray40", "gray70")  # Normal

            ctk.CTkLabel(frame, text=sec.get("Name", ""), font=ctk.CTkFont(size=10, family="Consolas")).grid(row=i, column=0, padx=8, pady=2, sticky="w")
            ctk.CTkLabel(frame, text=f"{sec.get('VirtualSize', 0):,}", font=ctk.CTkFont(size=10)).grid(row=i, column=1, padx=8, pady=2, sticky="w")
            ctk.CTkLabel(frame, text=f"{entropy:.2f}", font=ctk.CTkFont(size=10, weight="bold"), text_color=entropy_color).grid(row=i, column=2, padx=8, pady=2, sticky="w")
            chars = sec.get("Characteristics", "")[:25]
            ctk.CTkLabel(frame, text=chars, font=ctk.CTkFont(size=9)).grid(row=i, column=3, padx=8, pady=2, sticky="w")

    def _build_imports_content(self, frame: ctk.CTkFrame, imports: Dict):
        """Build imports content"""
        import_list = imports.get("imports", [])
        for i, imp in enumerate(import_list[:12]):
            dll = imp.get("dll", "")
            funcs = imp.get("functions", [])

            dll_frame = ctk.CTkFrame(frame, fg_color="transparent")
            dll_frame.pack(fill="x", padx=5, pady=2)

            ctk.CTkLabel(dll_frame, text=dll, font=ctk.CTkFont(size=11, weight="bold"), text_color=("#F39C12", "#F5B041")).pack(anchor="w")
            # Extract function names - handle both dict and string formats
            func_names = []
            for f in funcs[:6]:
                if isinstance(f, dict):
                    func_names.append(f.get("name", str(f)))
                else:
                    func_names.append(str(f))
            func_text = ", ".join(func_names) + (f" (+{len(funcs)-6} more)" if len(funcs) > 6 else "")
            ctk.CTkLabel(dll_frame, text=func_text, font=ctk.CTkFont(size=9), text_color=("gray50", "gray60"), wraplength=280).pack(anchor="w", padx=15)

        if len(import_list) > 12:
            ctk.CTkLabel(frame, text=f"... and {len(import_list) - 12} more DLLs", font=ctk.CTkFont(size=10), text_color=("gray50", "gray60")).pack(anchor="w", padx=10, pady=5)

    def _build_strings_content(self, frame: ctk.CTkFrame, strings: Dict):
        """Build strings content"""
        interesting = strings.get("interesting_strings", [])[:10]
        for i, s in enumerate(interesting):
            text = s[:65] + ("..." if len(s) > 65 else "")
            ctk.CTkLabel(frame, text=f"- {text}", font=ctk.CTkFont(size=10, family="Consolas"), text_color=("#1ABC9C", "#48C9B0")).pack(anchor="w", padx=10, pady=1)

    def _build_suspicious_content(self, frame: ctk.CTkFrame, indicators: List):
        """Build suspicious indicators content"""
        for i, ind in enumerate(indicators[:12]):
            text = ind[:70] + ("..." if len(ind) > 70 else "")
            ctk.CTkLabel(frame, text=f"- {text}", font=ctk.CTkFont(size=10), text_color="#E74C3C").pack(anchor="w", padx=10, pady=2)
        if len(indicators) > 12:
            ctk.CTkLabel(frame, text=f"... and {len(indicators) - 12} more", font=ctk.CTkFont(size=10), text_color=("gray50", "gray60")).pack(anchor="w", padx=10, pady=3)

    def _build_dll_features_content(self, frame: ctk.CTkFrame, dll_features: Dict):
        """Build DLL features content"""
        frame.grid_columnconfigure(1, weight=1)

        dll_info = dll_features.get("dll_info", {})
        dll_type = dll_features.get("dll_type_analysis", {})
        dll_chars = dll_features.get("dll_characteristics", {})
        exports = dll_features.get("exports", {})
        security = dll_chars.get("security_features", {})

        # Security score color
        security_score = dll_chars.get("security_score", 0)
        if security_score >= 75:
            score_color = "#27AE60"
        elif security_score >= 50:
            score_color = "#F39C12"
        else:
            score_color = "#E74C3C"

        # Risk level color
        risk_level = dll_info.get("risk_level", "NONE")
        if risk_level == "HIGH":
            risk_color = "#E74C3C"
        elif risk_level == "MEDIUM":
            risk_color = "#F39C12"
        else:
            risk_color = "#27AE60"

        items = [
            ("DLL Type", dll_type.get("type", "Unknown")),
            ("Subtypes", ", ".join(dll_type.get("subtypes", [])) or "None"),
            ("Exports", f"{exports.get('count', 0)} ({exports.get('named_count', 0)} named, {exports.get('ordinal_only_count', 0)} ordinal)"),
            ("Forwarded", str(len(dll_features.get("forwarded_functions", [])))),
            ("Security Score", f"{security_score}/100"),
            ("Risk Level", risk_level),
        ]

        for i, (label, value) in enumerate(items):
            label_color = "#8E44AD"
            value_color = ("gray20", "gray90")

            # Special coloring for security score and risk
            if label == "Security Score":
                value_color = score_color
            elif label == "Risk Level":
                value_color = risk_color

            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11), text_color=(label_color, "#BB8FCE")).grid(row=i, column=0, sticky="w", padx=10, pady=3)
            if isinstance(value_color, str):
                ctk.CTkLabel(frame, text=str(value), font=ctk.CTkFont(size=11, family="Consolas", weight="bold"), text_color=value_color).grid(row=i, column=1, sticky="w", padx=5, pady=3)
            else:
                ctk.CTkLabel(frame, text=str(value), font=ctk.CTkFont(size=11, family="Consolas")).grid(row=i, column=1, sticky="w", padx=5, pady=3)

        # Security features
        row = len(items)
        ctk.CTkLabel(frame, text="Security Features:", font=ctk.CTkFont(size=10), text_color=("#8E44AD", "#BB8FCE")).grid(row=row, column=0, sticky="w", padx=10, pady=(8, 3))

        security_text = []
        if security.get("aslr_enabled"):
            security_text.append("ASLR")
        if security.get("dep_enabled"):
            security_text.append("DEP")
        if security.get("cfg_enabled"):
            security_text.append("CFG")
        if security.get("high_entropy_va"):
            security_text.append("High Entropy")

        ctk.CTkLabel(frame, text=" | ".join(security_text) if security_text else "None", font=ctk.CTkFont(size=10, family="Consolas")).grid(row=row, column=1, sticky="w", padx=5, pady=(8, 3))

    def _build_details_view(self, result: Dict):
        """Build visual detailed view with cards - shows ALL data"""
        for widget in self.analysis_details_frame.winfo_children():
            widget.destroy()

        file_info = result.get("file_info", {})
        headers = result.get("headers", {})
        sections = result.get("sections", {})
        imports = result.get("imports", {})
        strings = result.get("strings", {})
        indicators = result.get("suspicious_indicators", [])

        # ═══════════════════════════════════════════════════════════════
        # FILE INFORMATION CARD
        # ═══════════════════════════════════════════════════════════════
        file_items = [
            ("Filename", file_info.get("filename", "N/A")),
            ("Full Path", file_info.get("filepath", "N/A")),
            ("Size", f"{file_info.get('size', 0):,} bytes"),
            ("Entropy", f"{file_info.get('entropy', 0):.6f} - {file_info.get('entropy_interpretation', '')}"),
            ("---", ""),
            ("MD5", file_info.get("md5", "N/A")),
            ("SHA1", file_info.get("sha1", "N/A")),
            ("SHA256", file_info.get("sha256", "N/A")),
            ("Imphash", file_info.get("imphash", "N/A")),
        ]
        if file_info.get("ssdeep"):
            file_items.append(("SSDeep", file_info.get("ssdeep")))

        self._add_detail_card("FILE INFORMATION", "#3498DB", file_items)

        # ═══════════════════════════════════════════════════════════════
        # PE HEADERS CARD
        # ═══════════════════════════════════════════════════════════════
        file_hdr = headers.get("file_header", {})
        opt = headers.get("optional_header", {})
        dos = headers.get("dos_header", {})

        header_items = []
        if dos:
            header_items.append(("[ DOS HEADER ]", ""))
            for key, val in dos.items():
                header_items.append((f"  {key}", str(val)))
        if file_hdr:
            header_items.append(("---", ""))
            header_items.append(("[ FILE HEADER ]", ""))
            for key, val in file_hdr.items():
                header_items.append((f"  {key}", str(val)))
        if opt:
            header_items.append(("---", ""))
            header_items.append(("[ OPTIONAL HEADER ]", ""))
            for key, val in opt.items():
                if isinstance(val, int) and key in ['AddressOfEntryPoint', 'ImageBase', 'BaseOfCode', 'SectionAlignment', 'FileAlignment']:
                    header_items.append((f"  {key}", f"0x{val:X}"))
                else:
                    header_items.append((f"  {key}", str(val)))

        if header_items:
            self._add_detail_card("PE HEADERS", "#9B59B6", header_items)

        # ═══════════════════════════════════════════════════════════════
        # SECURITY FEATURES CARD (for both EXE and DLL)
        # ═══════════════════════════════════════════════════════════════
        dll_char = opt.get("DllCharacteristics", "0x0")
        try:
            if isinstance(dll_char, str):
                char_value = int(dll_char, 16)
            else:
                char_value = int(dll_char)
        except (ValueError, TypeError):
            char_value = 0

        # Calculate security score
        score = 0
        if char_value & 0x0040: score += 25  # ASLR
        if char_value & 0x0100: score += 25  # DEP
        if char_value & 0x4000: score += 25  # CFG
        if char_value & 0x0020: score += 15  # High Entropy
        if char_value & 0x0080: score += 10  # Force Integrity

        security_items = [
            ("Security Score", f"{score}/100"),
            ("---", ""),
            ("ASLR", "✓ Enabled" if char_value & 0x0040 else "✗ Disabled"),
            ("DEP/NX", "✓ Enabled" if char_value & 0x0100 else "✗ Disabled"),
            ("CFG", "✓ Enabled" if char_value & 0x4000 else "✗ Disabled"),
            ("High Entropy VA", "✓ Enabled" if char_value & 0x0020 else "✗ Disabled"),
            ("Force Integrity", "✓ Enabled" if char_value & 0x0080 else "✗ Disabled"),
            ("No SEH", "Yes" if char_value & 0x0400 else "No"),
        ]
        self._add_detail_card("SECURITY FEATURES", "#16A085", security_items)

        # ═══════════════════════════════════════════════════════════════
        # SECTIONS CARD (ALL)
        # ═══════════════════════════════════════════════════════════════
        sections_list = sections.get("sections", [])
        if sections_list:
            section_items = []
            for i, sec in enumerate(sections_list):
                if i > 0:
                    section_items.append(("---", ""))

                va = sec.get('VirtualAddress', 0)
                vs = sec.get('VirtualSize', 0)
                srd = sec.get('SizeOfRawData', 0)
                ptrd = sec.get('PointerToRawData', 0)
                ent = sec.get('Entropy', 0)

                va_str = va if isinstance(va, str) else f"0x{va:08X}"
                vs_str = vs if isinstance(vs, str) else f"{vs:,}"
                srd_str = srd if isinstance(srd, str) else f"{srd:,}"
                ptrd_str = ptrd if isinstance(ptrd, str) else f"0x{ptrd:08X}"
                ent_str = ent if isinstance(ent, str) else f"{ent:.4f}"

                # Entropy warning
                ent_val = float(ent) if isinstance(ent, (int, float)) else 0
                ent_warning = " [HIGH]" if ent_val > 7.2 else " [MEDIUM]" if ent_val > 6.5 else ""

                section_items.append((f"[{i+1}] {sec.get('Name', 'Unknown')}", ""))
                section_items.append(("  VirtualAddress", va_str))
                section_items.append(("  VirtualSize", f"{vs_str} bytes"))
                section_items.append(("  SizeOfRawData", f"{srd_str} bytes"))
                section_items.append(("  PointerToRawData", ptrd_str))
                section_items.append(("  Entropy", f"{ent_str}{ent_warning}"))
                section_items.append(("  Characteristics", sec.get('Characteristics', 'N/A')))

            self._add_detail_card(f"SECTIONS ({len(sections_list)})", "#27AE60", section_items)

        # ═══════════════════════════════════════════════════════════════
        # IMPORTS CARD (ALL DLLs and ALL Functions)
        # ═══════════════════════════════════════════════════════════════
        import_list = imports.get("imports", [])
        if import_list:
            total_funcs = sum(len(imp.get("functions", [])) for imp in import_list)
            import_items = []

            for idx, imp in enumerate(import_list):
                if idx > 0:
                    import_items.append(("---", ""))

                dll = imp.get("dll", "Unknown")
                funcs = imp.get("functions", [])
                import_items.append((f"[{dll}]", f"({len(funcs)} functions)"))

                for f in funcs:
                    if isinstance(f, dict):
                        name = f.get("name", "Unknown")
                        addr = f.get("address", "")
                        ordinal = f.get("ordinal", "")
                        if addr:
                            import_items.append((f"  {name}", f"@ {addr}"))
                        else:
                            import_items.append((f"  {name}", f"Ordinal: {ordinal}" if ordinal else ""))
                    else:
                        import_items.append((f"  {f}", ""))

            self._add_detail_card(f"IMPORTS ({len(import_list)} DLLs, {total_funcs} functions)", "#F39C12", import_items)

        # ═══════════════════════════════════════════════════════════════
        # EXPORTS CARD (ALL)
        # ═══════════════════════════════════════════════════════════════
        exports = imports.get("exports", {})
        export_funcs = exports.get("functions", [])
        if export_funcs:
            export_items = []
            for exp in export_funcs:
                if isinstance(exp, dict):
                    name = exp.get("name", "Unknown")
                    addr = exp.get("address", "")
                    ordinal = exp.get("ordinal", "")
                    export_items.append((name, f"@ {addr} (Ordinal: {ordinal})"))
                else:
                    export_items.append((str(exp), ""))
            self._add_detail_card(f"EXPORTS ({len(export_funcs)})", "#1ABC9C", export_items)

        # ═══════════════════════════════════════════════════════════════
        # SUSPICIOUS APIs CARD (ALL)
        # ═══════════════════════════════════════════════════════════════
        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            total_apis = sum(len(v) for v in suspicious_apis.values())
            api_items = []
            for category, apis in suspicious_apis.items():
                if apis:
                    if api_items:
                        api_items.append(("---", ""))
                    api_items.append((f"[{category.upper()}]", f"({len(apis)})"))
                    for api in apis:
                        api_items.append((f"  {api}", ""))
            self._add_detail_card(f"SUSPICIOUS APIs ({total_apis})", "#E74C3C", api_items)

        # ═══════════════════════════════════════════════════════════════
        # STRINGS CARD (ALL)
        # ═══════════════════════════════════════════════════════════════
        interesting_strings = strings.get("interesting_strings", [])
        urls = strings.get("urls", [])
        ips = strings.get("ip_addresses", [])
        paths = strings.get("file_paths", [])
        registry = strings.get("registry_keys", [])

        if urls or ips or paths or registry or interesting_strings:
            string_items = []

            if urls:
                string_items.append((f"[URLs]", f"({len(urls)})"))
                for u in urls:
                    string_items.append((f"  {u}", ""))

            if ips:
                if string_items:
                    string_items.append(("---", ""))
                string_items.append((f"[IP Addresses]", f"({len(ips)})"))
                for ip in ips:
                    string_items.append((f"  {ip}", ""))

            if paths:
                if string_items:
                    string_items.append(("---", ""))
                string_items.append((f"[File Paths]", f"({len(paths)})"))
                for p in paths:
                    string_items.append((f"  {p}", ""))

            if registry:
                if string_items:
                    string_items.append(("---", ""))
                string_items.append((f"[Registry Keys]", f"({len(registry)})"))
                for r in registry:
                    string_items.append((f"  {r}", ""))

            if interesting_strings:
                if string_items:
                    string_items.append(("---", ""))
                string_items.append((f"[Interesting]", f"({len(interesting_strings)})"))
                for s in interesting_strings:
                    string_items.append((f"  {s}", ""))

            total_strings = len(urls) + len(ips) + len(paths) + len(registry) + len(interesting_strings)
            self._add_detail_card(f"STRINGS ({total_strings})", "#1ABC9C", string_items)

        # ═══════════════════════════════════════════════════════════════
        # SUSPICIOUS INDICATORS CARD (ALL)
        # ═══════════════════════════════════════════════════════════════
        if indicators:
            ind_items = [(f"[{i:02d}] {ind}", "") for i, ind in enumerate(indicators, 1)]
            self._add_detail_card(f"SUSPICIOUS INDICATORS ({len(indicators)})", "#E74C3C", ind_items)

        # ═══════════════════════════════════════════════════════════════
        # DLL FEATURES CARD (if DLL)
        # ═══════════════════════════════════════════════════════════════
        dll_features = result.get("dll_features", {})
        if dll_features and dll_features.get("is_dll"):
            self._build_dll_details_card(dll_features)

    def _build_dll_details_card(self, dll_features: Dict):
        """Build detailed DLL features card"""
        dll_info = dll_features.get("dll_info", {})
        dll_type = dll_features.get("dll_type_analysis", {})
        dll_chars = dll_features.get("dll_characteristics", {})
        exports = dll_features.get("exports", {})
        forwarded = dll_features.get("forwarded_functions", [])
        indicators = dll_features.get("suspicious_indicators", [])
        security = dll_chars.get("security_features", {})

        # DLL Info Card
        dll_items = [
            ("[ GENERAL ]", ""),
            ("  DLL Type", dll_type.get("type", "Unknown")),
            ("  Subtypes", ", ".join(dll_type.get("subtypes", [])) or "None"),
            ("  Risk Level", dll_info.get("risk_level", "NONE")),
            ("  Risk Score", f"{dll_info.get('risk_score', 0)}/100"),
            ("---", ""),
            ("[ SECURITY ]", ""),
            ("  Security Score", f"{dll_chars.get('security_score', 0)}/100"),
            ("  ASLR", "Enabled" if security.get("aslr_enabled") else "Disabled"),
            ("  DEP", "Enabled" if security.get("dep_enabled") else "Disabled"),
            ("  CFG", "Enabled" if security.get("cfg_enabled") else "Disabled"),
            ("  High Entropy VA", "Enabled" if security.get("high_entropy_va") else "Disabled"),
            ("  Force Integrity", "Enabled" if security.get("force_integrity") else "Disabled"),
            ("  No SEH", "Yes" if security.get("no_seh") else "No"),
            ("---", ""),
            ("[ EXPORTS ]", ""),
            ("  Total Count", str(exports.get("count", 0))),
            ("  Named Exports", str(exports.get("named_count", 0))),
            ("  Ordinal-Only", str(exports.get("ordinal_only_count", 0))),
            ("  Forwarded", str(len(forwarded))),
        ]

        # Add export categories
        categories = exports.get("categories", {})
        if categories:
            dll_items.append(("---", ""))
            dll_items.append(("[ EXPORT CATEGORIES ]", ""))
            for cat, funcs in categories.items():
                if funcs:
                    dll_items.append((f"  {cat.replace('_', ' ').title()}", str(len(funcs))))

        self._add_detail_card("DLL ANALYSIS", "#8E44AD", dll_items)

        # DLL Exports Card (show first 30)
        export_funcs = exports.get("functions", [])
        if export_funcs:
            export_items = []
            for i, exp in enumerate(export_funcs[:30]):
                name = exp.get("name") or f"Ordinal_{exp.get('ordinal', '?')}"
                addr = exp.get("address", "")
                is_fwd = exp.get("is_forwarded", False)
                forwarder = exp.get("forwarder", "")

                if is_fwd:
                    export_items.append((f"  {name}", f"-> {forwarder}", "#F39C12"))
                else:
                    export_items.append((f"  {name}", addr))

            if len(export_funcs) > 30:
                export_items.append(("---", ""))
                export_items.append((f"  ... and {len(export_funcs) - 30} more exports", ""))

            self._add_detail_card(f"DLL EXPORTS ({len(export_funcs)})", "#9B59B6", export_items)

        # DLL Suspicious Indicators
        if indicators:
            sus_items = []
            for ind in indicators:
                severity = ind.get("severity", "info").upper()
                desc = ind.get("description", "")
                if severity == "HIGH":
                    sus_items.append((f"[{severity}] {desc}", "", "#E74C3C"))
                elif severity == "MEDIUM":
                    sus_items.append((f"[{severity}] {desc}", "", "#F39C12"))
                else:
                    sus_items.append((f"[{severity}] {desc}", ""))

            self._add_detail_card(f"DLL SUSPICIOUS ({len(indicators)})", "#E74C3C", sus_items)

    def _add_detail_card(self, title: str, color: str, items: list):
        """Add a detailed card to the details panel"""
        card = ctk.CTkFrame(self.analysis_details_frame, corner_radius=12, fg_color=("white", "gray20"))
        card.pack(fill="x", pady=5, padx=2)
        card.grid_columnconfigure(1, weight=1)

        # Title bar
        title_bar = ctk.CTkFrame(card, corner_radius=0, fg_color=(color, color), height=32)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)
        ctk.CTkLabel(
            title_bar, text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="white"
        ).pack(side="left", padx=12, pady=6)

        # Content
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=10, pady=8)
        content.grid_columnconfigure(1, weight=1)

        row = 0
        for item in items:
            # Support both (label, value) and (label, value, custom_color)
            if len(item) == 3:
                label, value, item_color = item
            else:
                label, value = item
                item_color = None

            if label == "---":
                # Separator
                sep = ctk.CTkFrame(content, height=1, fg_color=("gray80", "gray40"))
                sep.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
            elif value == "":
                # Section header - use custom color or default card color
                header_color = item_color if item_color else color
                ctk.CTkLabel(
                    content, text=label,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=(header_color, header_color)
                ).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
            else:
                # Key-value pair
                ctk.CTkLabel(
                    content, text=label,
                    font=ctk.CTkFont(size=10),
                    text_color=("gray50", "gray60")
                ).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=1)
                # Use custom color for value if provided
                value_color = item_color if item_color else ("gray20", "gray90")
                if item_color:
                    value_color = (item_color, item_color)
                ctk.CTkLabel(
                    content, text=value,
                    font=ctk.CTkFont(size=10, family="Consolas"),
                    text_color=value_color
                ).grid(row=row, column=1, sticky="w", pady=1)
            row += 1

    def _display_folder_analysis(self, results: List[Dict], total_sections: int, total_imports: int, total_suspicious: int):
        """Display folder analysis results"""
        # Update stat cards
        self.stat_cards["sections"].set_value(str(total_sections))
        self.stat_cards["imports"].set_value(str(total_imports))
        self.stat_cards["suspicious"].set_value(str(total_suspicious))

        # Store for toggle
        self._folder_results = results

        # Clear and populate tree
        for widget in self.analysis_tree_frame.winfo_children():
            widget.destroy()

        row = 0

        # Folder summary
        summary_frame = ctk.CTkFrame(self.analysis_tree_frame, corner_radius=10, fg_color=("#E8F4FD", "#1a3a4a"))
        summary_frame.grid(row=row, column=0, sticky="ew", pady=(5, 10), padx=2)
        summary_frame.grid_columnconfigure(0, weight=1)

        stats_row = ctk.CTkFrame(summary_frame, fg_color="transparent")
        stats_row.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(stats_row, text=f"{len(results)} files analyzed", font=ctk.CTkFont(size=14, weight="bold"), text_color=("#1F6AA5", "#5DADE2")).pack(side="left")

        clean_count = sum(1 for r in results if not r.get("suspicious_indicators", []))
        susp_count = len(results) - clean_count
        ctk.CTkLabel(stats_row, text=f"{clean_count} clean", font=ctk.CTkFont(size=11), text_color=("#27AE60", "#2ECC71")).pack(side="right", padx=10)
        if susp_count > 0:
            ctk.CTkLabel(stats_row, text=f"{susp_count} suspicious", font=ctk.CTkFont(size=11), text_color="#E74C3C").pack(side="right", padx=10)
        row += 1

        # File list - show each file with suspicious indicators only
        for idx, result in enumerate(results):
            filepath = result.get("_filepath", "Unknown")
            filename = Path(filepath).name
            file_info = result.get("file_info", {})
            indicators = result.get("suspicious_indicators", [])
            section_id = f"folder_file_{idx}"

            is_collapsed = self.collapsed_sections.get(section_id, True)  # Default collapsed

            # Color based on suspicious indicators
            name_color = "#E74C3C" if indicators else ("#27AE60", "#2ECC71")
            status = f"[!{len(indicators)}]" if indicators else "[OK]"
            bg_color = ("#FEF0F0", "#3a2020") if indicators else ("gray95", "gray20")

            # File header (clickable)
            file_frame = ctk.CTkFrame(self.analysis_tree_frame, corner_radius=8, fg_color=bg_color)
            file_frame.grid(row=row, column=0, sticky="ew", pady=2, padx=2)
            file_frame.grid_columnconfigure(1, weight=1)
            row += 1

            # Toggle button (only for files with indicators)
            if indicators:
                toggle_text = "▶" if is_collapsed else "▼"
                toggle_btn = ctk.CTkButton(
                    file_frame, text=toggle_text, width=25, height=25,
                    fg_color="transparent", hover_color=("gray85", "gray30"),
                    text_color=name_color, font=ctk.CTkFont(size=10),
                    command=lambda sid=section_id: self._toggle_folder_file(sid)
                )
                toggle_btn.grid(row=0, column=0, padx=5, pady=8)
            else:
                # Spacer for clean files
                ctk.CTkLabel(file_frame, text="", width=25).grid(row=0, column=0, padx=5, pady=8)

            # File name and basic info
            info_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
            info_frame.grid(row=0, column=1, sticky="ew", pady=8, padx=5)

            ctk.CTkLabel(info_frame, text=f"{status} {filename}", font=ctk.CTkFont(size=11, weight="bold"), text_color=name_color).pack(side="left")

            entropy = file_info.get("entropy", 0)
            entropy_color = "#E74C3C" if entropy > 7.0 else "#F39C12" if entropy > 6.5 else ("gray50", "gray60")
            ctk.CTkLabel(info_frame, text=f"E:{entropy:.1f}", font=ctk.CTkFont(size=10), text_color=entropy_color).pack(side="right", padx=5)

            size = file_info.get("size", 0)
            ctk.CTkLabel(info_frame, text=f"{size:,}B", font=ctk.CTkFont(size=10), text_color=("gray50", "gray60")).pack(side="right", padx=5)

            # Expanded content - ONLY show suspicious indicators (no other details)
            if not is_collapsed and indicators:
                content_frame = ctk.CTkFrame(self.analysis_tree_frame, corner_radius=6, fg_color=("gray95", "gray17"))
                content_frame.grid(row=row, column=0, sticky="ew", pady=(0, 5), padx=10)
                content_frame.grid_columnconfigure(0, weight=1)
                row += 1

                # Show ALL suspicious indicators only
                for j, ind in enumerate(indicators):
                    ctk.CTkLabel(content_frame, text=f"[{j+1}] {ind}", font=ctk.CTkFont(size=9), text_color="#E74C3C", wraplength=380).pack(anchor="w", padx=10, pady=2)

        # Details panel - formatted summary
        self._build_folder_details_view(results)

        self.show_analysis()

    def _toggle_folder_file(self, section_id: str):
        """Toggle folder file collapsed state"""
        self.collapsed_sections[section_id] = not self.collapsed_sections.get(section_id, True)
        if hasattr(self, '_folder_results'):
            # Recalculate totals
            total_sections = sum(r.get("sections", {}).get("count", 0) for r in self._folder_results)
            total_imports = sum(len(r.get("imports", {}).get("imports", [])) for r in self._folder_results)
            total_suspicious = sum(len(r.get("suspicious_indicators", [])) for r in self._folder_results)
            self._display_folder_analysis(self._folder_results, total_sections, total_imports, total_suspicious)

    def _build_folder_details_view(self, results: List[Dict]):
        """Build folder analysis details view"""
        for widget in self.analysis_details_frame.winfo_children():
            widget.destroy()

        # Summary card
        summary_card = ctk.CTkFrame(self.analysis_details_frame, corner_radius=12, fg_color=("white", "gray20"))
        summary_card.pack(fill="x", pady=5, padx=2)

        title_bar = ctk.CTkFrame(summary_card, corner_radius=0, fg_color=("#3498DB", "#1F6AA5"), height=35)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)
        ctk.CTkLabel(title_bar, text="Folder Analysis Summary", font=ctk.CTkFont(size=13, weight="bold"), text_color="white").pack(side="left", padx=12, pady=8)

        # Stats
        stats_frame = ctk.CTkFrame(summary_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=10, pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        clean_count = sum(1 for r in results if not r.get("suspicious_indicators", []))
        susp_count = len(results) - clean_count
        total_size = sum(r.get("file_info", {}).get("size", 0) for r in results)
        avg_entropy = sum(r.get("file_info", {}).get("entropy", 0) for r in results) / len(results) if results else 0

        stats = [
            ("Total Files", str(len(results)), "#3498DB"),
            ("Clean", str(clean_count), "#27AE60"),
            ("Suspicious", str(susp_count), "#E74C3C"),
            ("Avg Entropy", f"{avg_entropy:.2f}", "#9B59B6"),
        ]

        for i, (label, value, color) in enumerate(stats):
            stat_box = ctk.CTkFrame(stats_frame, fg_color=("gray90", "gray25"), corner_radius=8)
            stat_box.grid(row=0, column=i, padx=4, pady=4, sticky="ew")
            ctk.CTkLabel(stat_box, text=value, font=ctk.CTkFont(size=18, weight="bold"), text_color=color).pack(pady=(8, 2))
            ctk.CTkLabel(stat_box, text=label, font=ctk.CTkFont(size=9), text_color=("gray50", "gray60")).pack(pady=(0, 8))

        # Suspicious files list
        suspicious_files = [r for r in results if r.get("suspicious_indicators", [])]
        if suspicious_files:
            susp_card = ctk.CTkFrame(self.analysis_details_frame, corner_radius=12, fg_color=("#FDEDEC", "#4a1a1a"))
            susp_card.pack(fill="x", pady=5, padx=2)

            ctk.CTkLabel(susp_card, text=f"Suspicious Files ({len(suspicious_files)})", font=ctk.CTkFont(size=12, weight="bold"), text_color="#E74C3C").pack(anchor="w", padx=12, pady=(10, 5))

            for r in suspicious_files[:8]:
                filename = Path(r.get("_filepath", "Unknown")).name
                ind_count = len(r.get("suspicious_indicators", []))
                ctk.CTkLabel(susp_card, text=f"- {filename} ({ind_count} indicators)", font=ctk.CTkFont(size=10), text_color="#E74C3C").pack(anchor="w", padx=20, pady=1)

            if len(suspicious_files) > 8:
                ctk.CTkLabel(susp_card, text=f"... and {len(suspicious_files) - 8} more", font=ctk.CTkFont(size=9), text_color=("gray50", "gray60")).pack(anchor="w", padx=20, pady=(2, 10))
            else:
                ctk.CTkFrame(susp_card, height=10, fg_color="transparent").pack()

        # Clean files summary
        clean_files = [r for r in results if not r.get("suspicious_indicators", [])]
        if clean_files:
            clean_card = ctk.CTkFrame(self.analysis_details_frame, corner_radius=12, fg_color=("#E8F8F5", "#1a3a2a"))
            clean_card.pack(fill="x", pady=5, padx=2)

            ctk.CTkLabel(clean_card, text=f"Clean Files ({len(clean_files)})", font=ctk.CTkFont(size=12, weight="bold"), text_color=("#27AE60", "#2ECC71")).pack(anchor="w", padx=12, pady=(10, 5))

            for r in clean_files:
                filename = Path(r.get("_filepath", "Unknown")).name
                file_info = r.get("file_info", {})
                entropy = file_info.get("entropy", 0)
                size = file_info.get("size", 0)
                ctk.CTkLabel(clean_card, text=f"- {filename} | {size:,}B | E:{entropy:.2f}", font=ctk.CTkFont(size=10), text_color=("#27AE60", "#2ECC71")).pack(anchor="w", padx=20, pady=1)

            ctk.CTkFrame(clean_card, height=10, fg_color="transparent").pack()

        # ═══════════════════════════════════════════════════════════════
        # DETAILED CARDS FOR SUSPICIOUS FILES ONLY
        # ═══════════════════════════════════════════════════════════════
        for result in suspicious_files:
            filepath = result.get("_filepath", "Unknown")
            filename = Path(filepath).name
            file_info = result.get("file_info", {})
            indicators = result.get("suspicious_indicators", [])
            sections_data = result.get("sections", {})
            imports_data = result.get("imports", {})
            headers_data = result.get("headers", {})

            # Build detailed items for suspicious file
            file_items = [
                # Basic Info - Blue
                ("[ FILE INFO ]", "", "#3498DB"),
                ("Filename", filename),
                ("Full Path", filepath),
                ("Size", f"{file_info.get('size', 0):,} bytes"),
                ("File Type", file_info.get("file_type", "N/A")),
                ("Entropy", f"{file_info.get('entropy', 0):.4f}"),
                ("---", ""),
                # Hashes - Purple
                ("[ HASHES ]", "", "#9B59B6"),
                ("MD5", file_info.get("md5", "N/A")),
                ("SHA1", file_info.get("sha1", "N/A")),
                ("SHA256", file_info.get("sha256", "N/A")),
                ("---", ""),
                # PE Info - Orange
                ("[ PE INFO ]", "", "#F39C12"),
                ("Sections", str(sections_data.get("count", 0))),
                ("Imports", str(len(imports_data.get("imports", [])))),
            ]

            # Add PE header info
            opt = headers_data.get("optional_header", {})
            file_hdr = headers_data.get("file_header", {})
            if opt or file_hdr:
                entry_point = opt.get('AddressOfEntryPoint', 0)
                if isinstance(entry_point, int):
                    entry_point = f"0x{entry_point:08X}"
                file_items.append(("Entry Point", str(entry_point)))
                file_items.append(("Machine", file_hdr.get("Machine", "N/A")))
                file_items.append(("Timestamp", file_hdr.get("TimeDateStamp", "N/A")))

            # Add suspicious indicators - Red
            file_items.append(("---", ""))
            file_items.append((f"[ SUSPICIOUS INDICATORS ({len(indicators)}) ]", "", "#E74C3C"))
            for i, ind in enumerate(indicators, 1):
                file_items.append((f"  [{i:02d}] {ind}", "", "#E74C3C"))

            self._add_detail_card(f"[!] {filename}", "#E74C3C", file_items)

    def _run_batch_extraction(self):
        """Run feature extraction on current file or folder"""
        if self.current_folder:
            self._log(f"Starting feature extraction: {self.current_folder}")
            threading.Thread(target=self._do_batch_folder_extraction, daemon=True).start()
        elif self.current_file:
            self._log(f"Starting feature extraction: {Path(self.current_file).name}")
            threading.Thread(target=self._do_single_extraction, daemon=True).start()
        else:
            messagebox.showwarning("No Selection", "Please select a file or folder first using buttons above.")

    def _do_single_extraction(self):
        """Extract features from single file"""
        try:
            self.batch_results = []
            self.expanded_batch_rows = {}
            self.after(0, self._clear_batch_results)

            self.after(0, lambda: self.batch_status.configure(text=f"Extracting: {Path(self.current_file).name}"))
            self.after(0, lambda: self.batch_progress.set(0.5))

            pe = pefile.PE(self.current_file)
            features = self.ml_extractor.extract(pe, self.current_file)
            pe.close()

            # Add metadata
            label = self.batch_label_entry.get().strip()
            if label:
                features["label"] = label
            features["filename"] = Path(self.current_file).name
            features["filepath"] = self.current_file

            self.batch_results.append(features)

            self.after(0, lambda: self.batch_progress.set(1.0))
            self.after(0, self._display_batch_results)
            self.after(0, lambda: self.batch_status.configure(text=f"Complete: 1 file, {len(features)} features"))
            self._log(f"Extracted {len(features)} features")

        except Exception as e:
            self._log(f"Error: {e}")
            self.after(0, lambda: messagebox.showerror("Error", str(e)))

    def _do_batch_folder_extraction(self):
        """Extract features from folder"""
        pattern_input = self.batch_pattern_entry.get() or "*.exe,*.dll"
        recursive = self.recursive_var.get()
        label = self.batch_label_entry.get().strip()

        try:
            self.batch_results = []
            self.expanded_batch_rows = {}
            self.after(0, self._clear_batch_results)

            folder_path = Path(self.current_folder)

            # Support multiple patterns separated by comma
            patterns = [p.strip() for p in pattern_input.split(",") if p.strip()]
            files = []
            for pattern in patterns:
                if recursive:
                    files.extend(folder_path.rglob(pattern))
                else:
                    files.extend(folder_path.glob(pattern))

            # Remove duplicates while preserving order
            files = list(dict.fromkeys(files))

            if not files:
                self._log("No files found")
                self.after(0, lambda: self.batch_status.configure(text="No files found matching pattern"))
                return

            total = len(files)
            self._log(f"Found {total} files")

            success = 0
            for i, filepath in enumerate(files):
                try:
                    progress = (i + 1) / total
                    self.after(0, lambda p=progress: self.batch_progress.set(p))
                    self.after(0, lambda f=filepath.name, n=i+1, t=total: self.batch_status.configure(text=f"Extracting {n}/{t}: {f}"))

                    pe = pefile.PE(str(filepath))
                    features = self.ml_extractor.extract(pe, str(filepath))
                    pe.close()

                    features["filename"] = filepath.name
                    features["filepath"] = str(filepath)
                    if label:
                        features["label"] = label

                    self.batch_results.append(features)
                    success += 1
                    self._log(f"OK: {filepath.name}")

                except Exception as e:
                    self._log(f"FAIL: {filepath.name}: {e}")

            self.after(0, self._display_batch_results)
            self.after(0, lambda: self.batch_status.configure(text=f"Complete: {success}/{total} files extracted"))
            self._log(f"Extraction complete: {success}/{total}")

        except Exception as e:
            self._log(f"Batch error: {e}")

    def _clear_batch_results(self):
        """Clear batch results display"""
        for widget in self.batch_results_scroll.winfo_children():
            widget.destroy()

    def _display_batch_results(self):
        """Display feature extraction results with expandable rows"""
        self._clear_batch_results()

        for idx, features in enumerate(self.batch_results):
            filename = features.get("filename", "Unknown")
            filepath = features.get("filepath", "")
            is_expanded = self.expanded_batch_rows.get(idx, False)

            # Get key stats from features
            entropy = features.get("file_entropy", 0)
            size = features.get("file_size", 0)
            sections = features.get("section_count", 0)
            imports = features.get("import_count", 0)
            anomaly = features.get("anomaly_score", 0)

            # Color based on anomaly score
            if anomaly > 0.5:
                bg_color = ("#F5E6E8", "#352828")
                status_color = ("#A04050", "#D4757F")  # Softer red/pink
            elif anomaly > 0.3:
                bg_color = ("#FEF9E7", "#3a3520")
                status_color = ("#C07020", "#E8A050")  # Softer orange
            else:
                bg_color = ("gray95", "gray20")
                status_color = ("#27AE60", "#58D68D")  # Green

            # Main row (clickable)
            row_frame = ctk.CTkFrame(self.batch_results_scroll, corner_radius=8, fg_color=bg_color, cursor="hand2")
            row_frame.pack(fill="x", pady=2, padx=2)
            row_frame.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Row content
            row_content = ctk.CTkFrame(row_frame, fg_color="transparent")
            row_content.pack(fill="x", padx=10, pady=8)
            row_content.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Toggle indicator
            toggle_text = "▼" if is_expanded else "▶"
            toggle_lbl = ctk.CTkLabel(row_content, text=toggle_text, font=ctk.CTkFont(size=12), text_color=status_color, width=20)
            toggle_lbl.pack(side="left")
            toggle_lbl.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Filename
            name_lbl = ctk.CTkLabel(row_content, text=filename, font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color)
            name_lbl.pack(side="left", padx=(5, 10))
            name_lbl.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Feature count
            feat_count = len(features)
            feat_lbl = ctk.CTkLabel(row_content, text=f"[{feat_count} features]", font=ctk.CTkFont(size=10), text_color=("gray50", "gray60"))
            feat_lbl.pack(side="left")
            feat_lbl.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Stats on right
            stats_text = f"E:{entropy:.2f} | A:{anomaly:.3f} | S:{sections} | I:{imports}"
            stats_lbl = ctk.CTkLabel(row_content, text=stats_text, font=ctk.CTkFont(size=10), text_color=("gray50", "gray60"))
            stats_lbl.pack(side="right")
            stats_lbl.bind("<Button-1>", lambda e, i=idx: self._toggle_batch_row(i))

            # Expanded feature table
            if is_expanded:
                self._build_feature_table(features, idx)

    def _toggle_batch_row(self, idx: int):
        """Toggle batch row expansion"""
        self.expanded_batch_rows[idx] = not self.expanded_batch_rows.get(idx, False)
        self._display_batch_results()

    def _build_feature_table(self, features: Dict, idx: int):
        """Build compact feature table with multiple columns - shows ALL features"""
        table_frame = ctk.CTkFrame(self.batch_results_scroll, corner_radius=8, fg_color=("white", "gray17"))
        table_frame.pack(fill="x", pady=(0, 8), padx=5)

        # Number of column pairs (feature | value)
        num_cols = 5  # 5 pairs = 10 columns total

        # Header row
        header = ctk.CTkFrame(table_frame, fg_color=("#3498DB", "#1F6AA5"), height=22)
        header.pack(fill="x")
        header.pack_propagate(False)

        for i in range(num_cols):
            header.grid_columnconfigure(i * 2, weight=2)
            header.grid_columnconfigure(i * 2 + 1, weight=1)
            ctk.CTkLabel(header, text="Feature", font=ctk.CTkFont(size=8, weight="bold"), text_color="white").grid(row=0, column=i*2, sticky="w", padx=3, pady=2)
            ctk.CTkLabel(header, text="Val", font=ctk.CTkFont(size=8, weight="bold"), text_color="white").grid(row=0, column=i*2+1, sticky="w", padx=3, pady=2)

        # Table content using grid
        content = ctk.CTkFrame(table_frame, fg_color="transparent")
        content.pack(fill="x")

        for i in range(num_cols):
            content.grid_columnconfigure(i * 2, weight=2)
            content.grid_columnconfigure(i * 2 + 1, weight=1)

        # Convert features to list for easier indexing
        feature_list = list(features.items())
        total_features = len(feature_list)
        rows_needed = (total_features + num_cols - 1) // num_cols

        for row in range(rows_needed):
            row_bg = ("gray95", "gray22") if row % 2 == 0 else ("white", "gray17")

            for col in range(num_cols):
                idx = row * num_cols + col

                if idx < total_features:
                    key, value = feature_list[idx]

                    # Format value compact
                    if isinstance(value, float):
                        val_text = f"{value:.3f}"
                    elif isinstance(value, bool):
                        val_text = "1" if value else "0"
                    elif isinstance(value, int):
                        val_text = str(value)
                    else:
                        val_text = str(value)[:20]
                else:
                    key, val_text = "", ""

                # Feature name cell
                name_cell = ctk.CTkFrame(content, fg_color=row_bg, height=18)
                name_cell.grid(row=row, column=col*2, sticky="ew", padx=0, pady=0)
                name_cell.grid_propagate(False)
                ctk.CTkLabel(name_cell, text=key, font=ctk.CTkFont(size=7), text_color=("gray30", "gray80")).pack(side="left", padx=3, pady=0)

                # Value cell
                value_cell = ctk.CTkFrame(content, fg_color=row_bg, height=18)
                value_cell.grid(row=row, column=col*2+1, sticky="ew", padx=0, pady=0)
                value_cell.grid_propagate(False)
                ctk.CTkLabel(value_cell, text=val_text, font=ctk.CTkFont(size=7, family="Consolas"), text_color=("gray20", "gray90")).pack(side="left", padx=3, pady=0)

        # Footer with total count
        footer = ctk.CTkFrame(table_frame, fg_color=("gray90", "gray25"), height=20)
        footer.pack(fill="x")
        footer.pack_propagate(False)
        ctk.CTkLabel(footer, text=f"Total: {len(features)} features", font=ctk.CTkFont(size=7, weight="bold"), text_color=("gray50", "gray60")).pack(side="left", padx=6, pady=2)

    def _export_batch_csv(self):
        """Export batch features to CSV"""
        if not self.batch_results:
            messagebox.showwarning("No Results", "No features to export.")
            return

        filepath = filedialog.asksaveasfilename(title="Export CSV", filetypes=[("CSV", "*.csv")], defaultextension=".csv")
        if filepath:
            try:
                from exowin.reporters import CSVReporter
                CSVReporter.generate_batch(self.batch_results, filepath)
                self._log(f"Exported: {filepath} ({len(self.batch_results)} samples)")
                messagebox.showinfo("Export Complete", f"Saved {len(self.batch_results)} samples to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_results(self):
        """Export current results"""
        if not self.current_results:
            messagebox.showwarning("No Results", "No results to export.")
            return

        data = self.current_results

        filetypes = [("JSON", "*.json"), ("HTML", "*.html"), ("Markdown", "*.md")]
        filepath = filedialog.asksaveasfilename(title="Export", filetypes=filetypes, defaultextension=".json")

        if filepath:
            try:
                ext = Path(filepath).suffix.lower()
                if ext == ".json":
                    self.reporters["JSON"].generate(data, filepath)
                elif ext == ".html":
                    self.reporters["HTML"].generate(data, filepath)
                elif ext == ".md":
                    self.reporters["Markdown"].generate(data, filepath)

                self._log(f"Exported to: {filepath}")
                messagebox.showinfo("Export Complete", f"Saved to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _log(self, message: str):
        """Add log message"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self._insert_log(f"[{timestamp}] {message}\n"))

    def _insert_log(self, message: str):
        """Insert log message"""
        self.log_text.insert("end", message)
        self.log_text.see("end")

    def _clear_log(self):
        """Clear log"""
        self.log_text.delete("1.0", "end")


def main():
    """Main entry point"""
    app = PEAnalyzerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()

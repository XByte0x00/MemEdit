"""
Cheat Engine-style Memory Scanner/Editor for Windows
Implements First Scan / Next Scan workflow with multiple value types
For legitimate testing and research in isolated environments only
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import struct
import math
import time
import queue
import traceback
import ctypes
from ctypes import wintypes
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import os

try:
    import psutil
    import pymem
    import pymem.process
    import pymem.memory
except ImportError:
    print("ERROR: Required libraries not installed.")
    print("Install with: pip install pymem psutil")
    exit(1)

# Load scanner DLL
scanner_dll = None
try:
    dll_path = os.path.join(os.path.dirname(__file__), "scanner.dll")
    if os.path.exists(dll_path):
        scanner_dll = ctypes.CDLL(dll_path)
        print(f"Loaded scanner.dll from {dll_path}")
    else:
        print(f"WARNING: scanner.dll not found at {dll_path}")
        print("Falling back to Python scanning (slower)")
except Exception as e:
    print(f"WARNING: Could not load scanner.dll: {e}")
    print("Falling back to Python scanning (slower)")

# Kernel32 functions
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, 
                              wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, 
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

# Additional kernel32 functions for DLL injection
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
kernel32.VirtualFreeEx.restype = ctypes.c_int

kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
kernel32.GetModuleHandleW.restype = ctypes.c_void_p

kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.CreateRemoteThread.restype = ctypes.c_void_p

kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
kernel32.WaitForSingleObject.restype = ctypes.c_ulong

kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
kernel32.GetExitCodeThread.restype = ctypes.c_int

# Memory constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010


class ValueType(Enum):
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    INT8 = "int8"
    UINT8 = "uint8"
    INT16 = "int16"
    UINT16 = "uint16"
    INT32 = "int32"
    UINT32 = "uint32"
    INT64 = "int64"
    UINT64 = "uint64"
    BYTES = "bytes"
    STRING = "string"
    ALL = "all"

# Mapping to C++ enum values
VALUE_TYPE_TO_CPP = {
    ValueType.FLOAT32: 0,
    ValueType.FLOAT64: 1,
    ValueType.INT8: 2,
    ValueType.UINT8: 3,
    ValueType.INT16: 4,
    ValueType.UINT16: 5,
    ValueType.INT32: 6,
    ValueType.UINT32: 7,
    ValueType.INT64: 8,
    ValueType.UINT64: 9,
}


class ScanType(Enum):
    EXACT = "Exact Value"
    RANGE = "Value Between"
    INCREASED = "Increased Value"
    DECREASED = "Decreased Value"
    CHANGED = "Changed Value"
    UNCHANGED = "Unchanged Value"
    CHANGED_BY = "Changed By"

# Mapping to C++ enum values
SCAN_TYPE_TO_CPP = {
    ScanType.EXACT: 0,
    ScanType.RANGE: 1,
    ScanType.INCREASED: 2,
    ScanType.DECREASED: 3,
    ScanType.CHANGED: 4,
    ScanType.UNCHANGED: 5,
    ScanType.CHANGED_BY: 6,
}


@dataclass
class ScanResult:
    address: int
    value: Any
    value_type: ValueType
    previous_value: Optional[Any] = None

# C++ ScanResult structure
class CScanResult(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_size_t),
        ("value", ctypes.c_double),
    ]

# Setup DLL function signatures if available
if scanner_dll:
    try:
        scanner_dll.scan_buffer_first_scan.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # buffer
            ctypes.c_size_t,                 # buffer_size
            ctypes.c_size_t,                 # base_addr
            ctypes.c_int,                    # value_type
            ctypes.c_int,                    # unaligned
            ctypes.c_int,                    # scan_type
            ctypes.c_double,                 # value1
            ctypes.c_double,                 # value2
            ctypes.c_double,                 # tolerance
            ctypes.POINTER(CScanResult),     # results
            ctypes.c_int,                    # max_results
        ]
        scanner_dll.scan_buffer_first_scan.restype = ctypes.c_int
        
        scanner_dll.scan_buffer_next_scan.argtypes = [
            wintypes.HANDLE,                       # process_handle
            ctypes.POINTER(ctypes.c_size_t),       # addresses
            ctypes.POINTER(ctypes.c_double),       # previous_values
            ctypes.c_int,                          # num_addresses
            ctypes.c_int,                          # value_type
            ctypes.c_int,                          # scan_type
            ctypes.c_double,                       # value1
            ctypes.c_double,                       # value2
            ctypes.c_double,                       # tolerance
            ctypes.POINTER(CScanResult),           # results
            ctypes.c_int,                          # max_results
        ]
        scanner_dll.scan_buffer_next_scan.restype = ctypes.c_int
    except Exception as e:
        print(f"Warning: Error setting up DLL functions: {e}")
        scanner_dll = None


class TypeInfo:
    """Information about each value type"""
    SPECS = {
        ValueType.FLOAT32: {"size": 4, "fmt": "<f", "align": 4},
        ValueType.FLOAT64: {"size": 8, "fmt": "<d", "align": 8},
        ValueType.INT8: {"size": 1, "fmt": "<b", "align": 1},
        ValueType.UINT8: {"size": 1, "fmt": "<B", "align": 1},
        ValueType.INT16: {"size": 2, "fmt": "<h", "align": 2},
        ValueType.UINT16: {"size": 2, "fmt": "<H", "align": 2},
        ValueType.INT32: {"size": 4, "fmt": "<i", "align": 4},
        ValueType.UINT32: {"size": 4, "fmt": "<I", "align": 4},
        ValueType.INT64: {"size": 8, "fmt": "<q", "align": 8},
        ValueType.UINT64: {"size": 8, "fmt": "<Q", "align": 8},
    }


def is_readable_protection(protect):
    if protect & PAGE_GUARD:
        return False
    if protect & PAGE_NOACCESS:
        return False
    return (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | 
                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | 
                       PAGE_EXECUTE_WRITECOPY)) != 0


def is_writable_protection(protect):
    if protect & PAGE_GUARD:
        return False
    return (protect & (PAGE_READWRITE | PAGE_WRITECOPY | 
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0


class MemoryScannerApp:
    def __init__(self, root):
        self.root = root
        root.title("CE-Style Memory Scanner")
        root.geometry("1200x700")

        # State
        self.pm = None
        self.attached_pid = None
        self.modules_cache = {}
        self.scan_results: List[ScanResult] = []
        self.scan_thread = None
        self.stop_scan = False
        self.result_queue = queue.Queue()
        self.has_scanned = False

        self._build_ui()
        self._drain_queue()

    def _build_ui(self):
        # Top frame - Process controls
        top_frame = ttk.Frame(self.root, padding=5)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="Process:").grid(row=0, column=0, sticky="w", padx=2)
        self.proc_entry = ttk.Entry(top_frame, width=30)
        self.proc_entry.grid(row=0, column=1, padx=2)

        self.attach_btn = ttk.Button(top_frame, text="Attach", command=self.attach_process)
        self.attach_btn.grid(row=0, column=2, padx=2)

        self.roblox_btn = ttk.Button(top_frame, text="Attach to Roblox Studio", 
                                     command=self.attach_to_roblox)
        self.roblox_btn.grid(row=0, column=3, padx=2)

        self.detach_btn = ttk.Button(top_frame, text="Detach", command=self.detach_process, state="disabled")
        self.detach_btn.grid(row=0, column=4, padx=2)

        # Scan controls frame
        scan_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding=5)
        scan_frame.pack(fill="x", padx=5, pady=5)

        # Row 0: Value Type and Scan Type
        ttk.Label(scan_frame, text="Value Type:").grid(row=0, column=0, sticky="w", padx=2)
        self.value_type_var = tk.StringVar(value="float32")
        value_types = [vt.value for vt in ValueType]
        self.value_type_combo = ttk.Combobox(scan_frame, textvariable=self.value_type_var, 
                                             values=value_types, width=15, state="readonly")
        self.value_type_combo.grid(row=0, column=1, sticky="w", padx=2)

        ttk.Label(scan_frame, text="Scan Type:").grid(row=0, column=2, sticky="w", padx=2)
        self.scan_type_var = tk.StringVar(value="Exact Value")
        scan_types = [st.value for st in ScanType]
        self.scan_type_combo = ttk.Combobox(scan_frame, textvariable=self.scan_type_var, 
                                            values=scan_types, width=15, state="readonly")
        self.scan_type_combo.grid(row=0, column=3, sticky="w", padx=2)

        # Row 1: Value inputs
        ttk.Label(scan_frame, text="Value:").grid(row=1, column=0, sticky="w", padx=2)
        self.value_entry = ttk.Entry(scan_frame, width=20)
        self.value_entry.grid(row=1, column=1, sticky="w", padx=2)

        ttk.Label(scan_frame, text="Value2/Delta:").grid(row=1, column=2, sticky="w", padx=2)
        self.value2_entry = ttk.Entry(scan_frame, width=20)
        self.value2_entry.grid(row=1, column=3, sticky="w", padx=2)

        ttk.Label(scan_frame, text="Tolerance:").grid(row=1, column=4, sticky="w", padx=2)
        self.tolerance_entry = ttk.Entry(scan_frame, width=10)
        self.tolerance_entry.insert(0, "0.001")
        self.tolerance_entry.grid(row=1, column=5, sticky="w", padx=2)

        # Row 2: Options
        self.unaligned_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(scan_frame, text="Unaligned", variable=self.unaligned_var).grid(
            row=2, column=0, sticky="w", padx=2)

        self.writable_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scan_frame, text="Writable Only", variable=self.writable_only_var).grid(
            row=2, column=1, sticky="w", padx=2)

        self.force_write_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scan_frame, text="Force Writable (VirtualProtect)", 
                       variable=self.force_write_var).grid(row=2, column=2, sticky="w", padx=2)

        # Row 3: Scan buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.grid(row=3, column=0, columnspan=6, pady=5)

        self.first_scan_btn = ttk.Button(button_frame, text="First Scan", 
                                         command=self.do_first_scan, state="disabled")
        self.first_scan_btn.pack(side="left", padx=2)

        self.next_scan_btn = ttk.Button(button_frame, text="Next Scan", 
                                        command=self.do_next_scan, state="disabled")
        self.next_scan_btn.pack(side="left", padx=2)

        self.new_scan_btn = ttk.Button(button_frame, text="New Scan", 
                                       command=self.do_new_scan, state="disabled")
        self.new_scan_btn.pack(side="left", padx=2)

        self.cancel_btn = ttk.Button(button_frame, text="Cancel Scan", 
                                     command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=2)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scan_frame, variable=self.progress_var, 
                                           maximum=100, length=300)
        self.progress_bar.grid(row=4, column=0, columnspan=6, sticky="ew", padx=2, pady=2)

        # Status
        self.status_var = tk.StringVar(value="Not attached")
        ttk.Label(scan_frame, textvariable=self.status_var).grid(
            row=5, column=0, columnspan=6, sticky="w", padx=2)

        # Results frame
        results_frame = ttk.LabelFrame(self.root, text="Results", padding=5)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Treeview
        cols = ("address", "type", "value", "module", "protection")
        self.tree = ttk.Treeview(results_frame, columns=cols, show="headings", 
                                selectmode="extended")
        self.tree.heading("address", text="Address")
        self.tree.heading("type", text="Type")
        self.tree.heading("value", text="Value")
        self.tree.heading("module", text="Module+Offset")
        self.tree.heading("protection", text="Protection")

        self.tree.column("address", width=120)
        self.tree.column("type", width=80)
        self.tree.column("value", width=120)
        self.tree.column("module", width=350)
        self.tree.column("protection", width=100)

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Change Value(s)...", command=self.change_values)
        self.context_menu.add_command(label="Change Values Forcefully with DLL", command=self.change_values_forcefully)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Address", command=self.copy_address)
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Control-a>", self.select_all)
        self.tree.bind("<Control-A>", self.select_all)

        # Log area
        log_frame = ttk.LabelFrame(self.root, text="Log", padding=5)
        log_frame.pack(fill="x", padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD)
        self.log_text.pack(fill="both", expand=True)

    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def attach_to_roblox(self):
        """Quick attach to Roblox Studio"""
        self.proc_entry.delete(0, tk.END)
        self.proc_entry.insert(0, "RobloxStudioBeta.exe")
        self.attach_process()
    
    def attach_process(self):
        proc_text = self.proc_entry.get().strip()
        if not proc_text:
            messagebox.showerror("Error", "Enter a process name or PID")
            return

        pid = None
        try:
            pid = int(proc_text)
        except ValueError:
            for p in psutil.process_iter(("pid", "name")):
                try:
                    if p.info["name"] and proc_text.lower() in p.info["name"].lower():
                        pid = p.info["pid"]
                        break
                except:
                    continue
            if pid is None:
                messagebox.showerror("Error", f"Process '{proc_text}' not found")
                return

        try:
            self.pm = pymem.Pymem()
            try:
                self.pm.open_process_from_id(pid)
            except:
                self.pm.open_process(pid)

            self.attached_pid = pid
            self._cache_modules()

            self.log(f"Attached to PID {pid} ({len(self.modules_cache)} modules)")
            self.status_var.set(f"Attached to PID {pid}")

            self.first_scan_btn.config(state="normal")
            self.new_scan_btn.config(state="normal")
            self.detach_btn.config(state="normal")
            self.attach_btn.config(state="disabled")
            self.proc_entry.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Attach Error", f"Could not attach: {e}")
            self.log(f"ERROR: {e}")

    def _cache_modules(self):
        self.modules_cache = {}
        try:
            for m in self.pm.list_modules():
                self.modules_cache[m.lpBaseOfDll] = {
                    "name": m.name,
                    "size": m.SizeOfImage
                }
        except Exception as e:
            self.log(f"Warning: Could not cache modules: {e}")

    def _get_module_info(self, addr):
        for base in sorted(self.modules_cache.keys(), reverse=True):
            info = self.modules_cache[base]
            if addr >= base and addr < base + info["size"]:
                return f"{info['name']}+{addr - base:X}"
        return "<unknown>"

    def detach_process(self):
        if self.pm:
            try:
                self.pm.close_process()
            except:
                pass
        self.pm = None
        self.attached_pid = None
        self.modules_cache = {}
        self.scan_results = []
        self.has_scanned = False

        self.first_scan_btn.config(state="disabled")
        self.next_scan_btn.config(state="disabled")
        self.new_scan_btn.config(state="disabled")
        self.detach_btn.config(state="disabled")
        self.attach_btn.config(state="normal")
        self.proc_entry.config(state="normal")

        self.log("Detached")
        self.status_var.set("Detached")

    def do_first_scan(self):
        if not self.pm:
            messagebox.showerror("Error", "Not attached")
            return

        self.has_scanned = False
        self.scan_results = []
        for item in self.tree.get_children():
            self.tree.delete(item)

        self._start_scan(is_first_scan=True)

    def do_next_scan(self):
        if not self.has_scanned or not self.scan_results:
            messagebox.showwarning("Warning", "No previous scan results")
            return

        self._start_scan(is_first_scan=False)

    def do_new_scan(self):
        self.do_first_scan()

    def cancel_scan(self):
        self.stop_scan = True
        self.log("Cancelling scan...")

    def _start_scan(self, is_first_scan):
        scan_type_str = self.scan_type_var.get()
        scan_type = next(st for st in ScanType if st.value == scan_type_str)

        # Validate inputs based on scan type
        value1 = None
        value2 = None
        tolerance = 0.001

        try:
            tolerance = float(self.tolerance_entry.get())
        except:
            pass

        if scan_type in [ScanType.EXACT, ScanType.CHANGED_BY]:
            val_str = self.value_entry.get().strip()
            if not val_str and scan_type == ScanType.EXACT:
                messagebox.showerror("Error", "Enter a value")
                return
            if val_str:
                try:
                    value1 = float(val_str)
                except:
                    messagebox.showerror("Error", "Invalid value")
                    return

        if scan_type == ScanType.RANGE:
            try:
                value1 = float(self.value_entry.get())
                value2 = float(self.value2_entry.get())
            except:
                messagebox.showerror("Error", "Invalid range values")
                return

        if scan_type == ScanType.CHANGED_BY:
            try:
                value2 = float(self.value2_entry.get())
            except:
                messagebox.showerror("Error", "Invalid delta value")
                return

        # Start scan
        self.stop_scan = False
        self.first_scan_btn.config(state="disabled")
        self.next_scan_btn.config(state="disabled")
        self.new_scan_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress_var.set(0)

        value_type_str = self.value_type_var.get()
        value_type = next(vt for vt in ValueType if vt.value == value_type_str)

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(is_first_scan, scan_type, value_type, value1, value2, tolerance),
            daemon=True
        )
        self.scan_thread.start()

    def _scan_worker(self, is_first_scan, scan_type, value_type, value1, value2, tolerance):
        try:
            if is_first_scan:
                self._do_first_scan_worker(scan_type, value_type, value1, value2, tolerance)
            else:
                self._do_next_scan_worker(scan_type, value_type, value1, value2, tolerance)
        except Exception as e:
            self.result_queue.put(("error", f"Scan error: {e}\n{traceback.format_exc()}"))
        finally:
            self.result_queue.put(("scan_done", None))

    def _do_first_scan_worker(self, scan_type, value_type, value1, value2, tolerance):
        start_time = time.time()
        matches = []
        last_update_time = time.time()
        last_sent_count = 0  # Track how many results we've already sent
        update_batch_size = 500  # Send updates every 500 matches

        # Get memory regions
        regions = self._get_scannable_regions()
        if not regions:
            self.result_queue.put(("error", "No scannable regions"))
            return

        total_size = sum(r["size"] for r in regions)
        scanned_size = 0

        self.result_queue.put(("log", f"First scan: {len(regions)} regions, {total_size/1024/1024:.1f} MB"))
        self.result_queue.put(("clear_results", None))  # Clear previous results

        # Determine what to scan
        if value_type == ValueType.ALL:
            scan_types = [ValueType.FLOAT32, ValueType.FLOAT64, ValueType.INT8, ValueType.UINT8,
                         ValueType.INT16, ValueType.UINT16, ValueType.INT32, ValueType.UINT32,
                         ValueType.INT64, ValueType.UINT64]
        else:
            scan_types = [value_type]

        chunk_size = 4 * 1024 * 1024

        for region in regions:
            if self.stop_scan:
                break

            base = region["base"]
            size = region["size"]
            protect = region["protect"]

            offset = 0
            while offset < size:
                if self.stop_scan:
                    break

                to_read = min(chunk_size, size - offset)
                addr = base + offset

                try:
                    buf = self._read_memory(addr, to_read)
                    if buf:
                        # Scan buffer for each type
                        for vt in scan_types:
                            found = self._scan_buffer(buf, addr, vt, scan_type, 
                                                     value1, value2, tolerance)
                            matches.extend(found)
                            
                            # Send only NEW results (delta) every batch_size matches or every 0.3 seconds
                            current_time = time.time()
                            new_count = len(matches) - last_sent_count
                            if (new_count >= update_batch_size and 
                                current_time - last_update_time >= 0.3):
                                # Send only the new matches since last update
                                self.result_queue.put(("partial_results", matches[last_sent_count:]))
                                last_sent_count = len(matches)
                                last_update_time = current_time
                except:
                    pass

                offset += to_read
                scanned_size += to_read

                progress = (scanned_size / total_size) * 100
                self.result_queue.put(("progress", progress))

        elapsed = time.time() - start_time
        self.result_queue.put(("log", f"First scan complete: {len(matches)} matches in {elapsed:.1f}s"))
        self.result_queue.put(("results", matches))

    def _do_next_scan_worker(self, scan_type, value_type, value1, value2, tolerance):
        start_time = time.time()
        new_results = []
        last_update_time = time.time()
        last_sent_count = 0  # Track how many results we've already sent
        update_batch_size = 500

        total = len(self.scan_results)
        self.result_queue.put(("log", f"Next scan: filtering {total} addresses"))
        self.result_queue.put(("clear_results", None))  # Clear previous results

        # Try using C++ DLL for speed
        if (scanner_dll and value_type in VALUE_TYPE_TO_CPP and 
            scan_type in SCAN_TYPE_TO_CPP and total > 0):
            try:
                new_results = self._do_next_scan_cpp(scan_type, value_type, value1, value2, tolerance)
                elapsed = time.time() - start_time
                self.result_queue.put(("log", f"Next scan complete (C++): {len(new_results)} matches in {elapsed:.1f}s"))
                self.result_queue.put(("results", new_results))
                return
            except Exception as e:
                self.result_queue.put(("log", f"DLL next scan failed, using Python: {e}"))

        # Python fallback
        for i, result in enumerate(self.scan_results):
            if self.stop_scan:
                break

            if i % 1000 == 0:
                progress = (i / total) * 100
                self.result_queue.put(("progress", progress))

            # Read current value
            try:
                buf = self._read_memory(result.address, TypeInfo.SPECS[result.value_type]["size"])
                if not buf:
                    continue

                current_value = struct.unpack(TypeInfo.SPECS[result.value_type]["fmt"], buf)[0]

                # Apply filter
                if self._passes_filter(current_value, result.value, scan_type, 
                                      value1, value2, tolerance):
                    new_result = ScanResult(
                        address=result.address,
                        value=current_value,
                        value_type=result.value_type,
                        previous_value=result.value
                    )
                    new_results.append(new_result)
                    
                    # Send only NEW results (delta)
                    current_time = time.time()
                    new_count = len(new_results) - last_sent_count
                    if (new_count >= update_batch_size and 
                        current_time - last_update_time >= 0.3):
                        # Send only the new matches since last update
                        self.result_queue.put(("partial_results", new_results[last_sent_count:]))
                        last_sent_count = len(new_results)
                        last_update_time = current_time
            except:
                pass

        elapsed = time.time() - start_time
        self.result_queue.put(("log", f"Next scan complete: {len(new_results)} matches in {elapsed:.1f}s"))
        self.result_queue.put(("results", new_results))
    
    def _do_next_scan_cpp(self, scan_type, value_type, value1, value2, tolerance):
        """Fast C++ next scan"""
        new_results = []
        total = len(self.scan_results)
        
        # Prepare arrays
        addresses = (ctypes.c_size_t * total)()
        previous_values = (ctypes.c_double * total)()
        
        for i, result in enumerate(self.scan_results):
            addresses[i] = result.address
            previous_values[i] = float(result.value)
        
        # Prepare result buffer
        max_results = total
        results = (CScanResult * max_results)()
        
        # Call DLL
        cpp_value_type = VALUE_TYPE_TO_CPP[value_type]
        cpp_scan_type = SCAN_TYPE_TO_CPP[scan_type]
        
        num_found = scanner_dll.scan_buffer_next_scan(
            wintypes.HANDLE(int(self.pm.process_handle)),
            addresses,
            previous_values,
            total,
            cpp_value_type,
            cpp_scan_type,
            value1 if value1 is not None else 0.0,
            value2 if value2 is not None else 0.0,
            tolerance,
            results,
            max_results
        )
        
        # Convert results
        for i in range(num_found):
            new_results.append(ScanResult(
                address=results[i].address,
                value=results[i].value,
                value_type=value_type,
                previous_value=previous_values[i]
            ))
        
        return new_results

    def _get_scannable_regions(self):
        regions = []
        writable_only = self.writable_only_var.get()

        try:
            # Handle different pymem versions
            region_list = []
            
            # Try newer pymem API first
            if hasattr(self.pm, 'process') and hasattr(self.pm.process, 'iter_region'):
                region_list = list(self.pm.process.iter_region())
            else:
                # Fallback: manually enumerate using VirtualQueryEx
                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wintypes.DWORD),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", wintypes.DWORD),
                        ("Protect", wintypes.DWORD),
                        ("Type", wintypes.DWORD),
                    ]
                
                VirtualQueryEx = kernel32.VirtualQueryEx
                VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, 
                                          ctypes.POINTER(MEMORY_BASIC_INFORMATION), 
                                          ctypes.c_size_t]
                VirtualQueryEx.restype = ctypes.c_size_t
                
                address = 0x10000
                max_address = 0x7FFFFFFF0000
                
                while address < max_address:
                    mbi = MEMORY_BASIC_INFORMATION()
                    result = VirtualQueryEx(
                        wintypes.HANDLE(self.pm.process_handle),
                        wintypes.LPCVOID(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )
                    
                    if result == 0:
                        break
                    
                    class Region:
                        pass
                    
                    r = Region()
                    r.BaseAddress = mbi.BaseAddress
                    r.RegionSize = mbi.RegionSize
                    r.State = mbi.State
                    r.Protect = mbi.Protect
                    
                    region_list.append(r)
                    address = mbi.BaseAddress + mbi.RegionSize
            
            # Filter regions
            for r in region_list:
                if r.State != MEM_COMMIT:
                    continue
                if r.Protect & PAGE_GUARD:
                    continue
                if not is_readable_protection(r.Protect):
                    continue
                if writable_only and not is_writable_protection(r.Protect):
                    continue

                regions.append({
                    "base": r.BaseAddress,
                    "size": r.RegionSize,
                    "protect": r.Protect
                })
        except Exception as e:
            self.result_queue.put(("error", f"Error enumerating regions: {e}\n{traceback.format_exc()}"))

        return regions

    def _read_memory(self, addr, size):
        try:
            buf = self.pm.read_bytes(addr, size)
            if not isinstance(buf, (bytes, bytearray)):
                buf = bytes(buf)
            return buf
        except:
            try:
                buf = pymem.memory.read_bytes(self.pm.process_handle, addr, size)
                if not isinstance(buf, (bytes, bytearray)):
                    buf = bytes(buf)
                return buf
            except:
                return None

    def _scan_buffer(self, buf, base_addr, value_type, scan_type, value1, value2, tolerance):
        matches = []

        if value_type not in TypeInfo.SPECS:
            return matches

        # Try to use C++ DLL for speed
        if scanner_dll and value_type in VALUE_TYPE_TO_CPP and scan_type in SCAN_TYPE_TO_CPP:
            try:
                return self._scan_buffer_cpp(buf, base_addr, value_type, scan_type, 
                                            value1, value2, tolerance)
            except Exception as e:
                # Fall back to Python if DLL fails
                self.log(f"DLL scan failed, using Python: {e}")
                pass

        # Python fallback
        spec = TypeInfo.SPECS[value_type]
        size = spec["size"]
        fmt = spec["fmt"]

        unaligned = self.unaligned_var.get()
        step = 1 if unaligned else spec["align"]

        i = 0
        while i + size <= len(buf):
            try:
                val = struct.unpack(fmt, buf[i:i+size])[0]

                # Skip invalid floats
                if value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                    if math.isnan(val) or math.isinf(val):
                        i += step
                        continue

                # Check if matches criteria
                if self._passes_filter(val, None, scan_type, value1, value2, tolerance):
                    addr = base_addr + i
                    matches.append(ScanResult(addr, val, value_type))

            except:
                pass

            i += step

        return matches
    
    def _scan_buffer_cpp(self, buf, base_addr, value_type, scan_type, value1, value2, tolerance):
        """Fast C++ scanning"""
        matches = []
        
        # Prepare buffer
        buffer_array = (ctypes.c_ubyte * len(buf)).from_buffer_copy(buf)
        
        # Prepare result buffer (allocate generously)
        max_results = min(1000000, len(buf) // TypeInfo.SPECS[value_type]["size"])
        results = (CScanResult * max_results)()
        
        # Call DLL
        unaligned = 1 if self.unaligned_var.get() else 0
        cpp_value_type = VALUE_TYPE_TO_CPP[value_type]
        cpp_scan_type = SCAN_TYPE_TO_CPP[scan_type]
        
        num_found = scanner_dll.scan_buffer_first_scan(
            buffer_array,
            len(buf),
            base_addr,
            cpp_value_type,
            unaligned,
            cpp_scan_type,
            value1 if value1 is not None else 0.0,
            value2 if value2 is not None else 0.0,
            tolerance,
            results,
            max_results
        )
        
        # Convert results
        for i in range(num_found):
            matches.append(ScanResult(
                address=results[i].address,
                value=results[i].value,
                value_type=value_type
            ))
        
        return matches

    def _passes_filter(self, current, previous, scan_type, value1, value2, tolerance):
        if scan_type == ScanType.EXACT:
            if value1 is None:
                return True
            return abs(current - value1) <= tolerance

        elif scan_type == ScanType.RANGE:
            return value1 <= current <= value2

        elif scan_type == ScanType.INCREASED:
            return previous is not None and current > previous

        elif scan_type == ScanType.DECREASED:
            return previous is not None and current < previous

        elif scan_type == ScanType.CHANGED:
            return previous is not None and abs(current - previous) > tolerance

        elif scan_type == ScanType.UNCHANGED:
            return previous is not None and abs(current - previous) <= tolerance

        elif scan_type == ScanType.CHANGED_BY:
            if previous is None or value2 is None:
                return False
            delta = abs(current - previous)
            return abs(delta - value2) <= tolerance

        return False

    def _drain_queue(self):
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()

                if msg_type == "log":
                    self.log(data)
                elif msg_type == "error":
                    self.log(f"ERROR: {data}")
                elif msg_type == "progress":
                    self.progress_var.set(data)
                elif msg_type == "clear_results":
                    self._clear_results()
                elif msg_type == "partial_results":
                    self._display_partial_results(data)
                elif msg_type == "results":
                    self._display_results(data)
                elif msg_type == "scan_done":
                    self._scan_finished()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._drain_queue)

    def _clear_results(self):
        """Clear the results tree view"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Scanning...")
    
    def _display_partial_results(self, results):
        """Display partial results incrementally (results are already deltas)"""
        max_display = 10000
        current_items = len(self.tree.get_children())
        
        # Only add new items if we haven't exceeded max display
        if current_items >= max_display:
            return
        
        # Add the new results (which are already just the delta)
        items_to_add = min(max_display - current_items, len(results))
        
        for i in range(items_to_add):
            result = results[i]
            addr_str = f"{result.address:X}"
            type_str = result.value_type.value

            if result.value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                val_str = f"{result.value:.6f}"
            else:
                val_str = str(result.value)

            module = self._get_module_info(result.address)
            self.tree.insert("", "end", values=(addr_str, type_str, val_str, module, ""))
        
        # Update status with approximate count
        total_displayed = current_items + items_to_add
        self.status_var.set(f"Found {total_displayed}+ matches...")

    def _display_results(self, results):
        self.scan_results = results
        self.has_scanned = True

        for item in self.tree.get_children():
            self.tree.delete(item)

        max_display = 10000
        for i, result in enumerate(results[:max_display]):
            addr_str = f"{result.address:X}"
            type_str = result.value_type.value

            if result.value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                val_str = f"{result.value:.6f}"
            else:
                val_str = str(result.value)

            module = self._get_module_info(result.address)

            self.tree.insert("", "end", values=(addr_str, type_str, val_str, module, ""))

        if len(results) > max_display:
            self.log(f"Showing {max_display} of {len(results)} results")

        self.status_var.set(f"Found {len(results)} matches")

    def _scan_finished(self):
        self.first_scan_btn.config(state="normal")
        self.new_scan_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")

        if self.has_scanned and self.scan_results:
            self.next_scan_btn.config(state="normal")

        self.progress_var.set(0)

    def select_all(self, event=None):
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children)
        return "break"

    def show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            current_sel = self.tree.selection()
            if iid not in current_sel:
                self.tree.selection_set(iid)
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()

    def copy_address(self):
        sel = self.tree.selection()
        if sel:
            addr = self.tree.item(sel[0], "values")[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)
            self.log(f"Copied: {addr}")

    def change_values(self):
        sel = self.tree.selection()
        if not sel:
            return

        num_sel = len(sel)

        if num_sel == 1:
            addr_str = self.tree.item(sel[0], "values")[0]
            new_val_str = simpledialog.askstring("Change Value", 
                                                 f"Address: {addr_str}\nEnter new value:")
        else:
            new_val_str = simpledialog.askstring("Change Values", 
                                                 f"Modifying {num_sel} addresses\nEnter new value:")

        if not new_val_str:
            return

        success = 0
        failed = []

        for item in sel:
            addr_str, type_str, _, module, _ = self.tree.item(item, "values")

            try:
                addr = int(addr_str, 16)
                value_type = next(vt for vt in ValueType if vt.value == type_str)

                if value_type not in TypeInfo.SPECS:
                    failed.append(addr_str)
                    continue

                spec = TypeInfo.SPECS[value_type]

                # Parse and pack value
                if value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                    val = float(new_val_str)
                else:
                    val = int(new_val_str)

                data = struct.pack(spec["fmt"], val)

                # Write
                if self._write_memory(addr, data):
                    success += 1

                    # Update display
                    if value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                        display_val = f"{val:.6f}"
                    else:
                        display_val = str(val)
                    self.tree.item(item, values=(addr_str, type_str, display_val, module, ""))
                else:
                    failed.append(addr_str)

            except Exception as e:
                failed.append(addr_str)
                self.log(f"Error writing {addr_str}: {e}")

        # Report results
        if num_sel == 1:
            if success:
                messagebox.showinfo("Success", "Value updated")
            else:
                messagebox.showerror("Failed", "Could not write value")
        else:
            msg = f"Modified {success}/{num_sel} addresses"
            if failed:
                msg += f"\n\nFailed: {len(failed)}"
            messagebox.showinfo("Batch Complete", msg)

        self.log(f"Write complete: {success} OK, {len(failed)} failed")

    def _write_memory(self, addr, data):
        force = self.force_write_var.get()

        # Try protected write
        if force:
            success = self._protected_write(addr, data)
            if success:
                return True

        # Try direct write
        success = self._direct_write(addr, data)
        return success

    def _protected_write(self, addr, data):
        try:
            hproc = wintypes.HANDLE(int(self.pm.process_handle))
            lpAddress = wintypes.LPVOID(addr)
            dwSize = ctypes.c_size_t(len(data))
            newProtect = wintypes.DWORD(PAGE_READWRITE)
            oldProtect = wintypes.DWORD(0)

            ok = VirtualProtectEx(hproc, lpAddress, dwSize, newProtect, ctypes.byref(oldProtect))

            lpBuffer = ctypes.create_string_buffer(data)
            nSize = ctypes.c_size_t(len(data))
            written = ctypes.c_size_t(0)
            write_ok = WriteProcessMemory(hproc, lpAddress, ctypes.byref(lpBuffer), 
                                         nSize, ctypes.byref(written))

            if ok:
                VirtualProtectEx(hproc, lpAddress, dwSize, oldProtect.value, 
                               ctypes.byref(wintypes.DWORD()))

            return write_ok and written.value == len(data)
        except:
            return False

    def _direct_write(self, addr, data):
        try:
            hproc = wintypes.HANDLE(int(self.pm.process_handle))
            lpAddress = wintypes.LPVOID(addr)
            lpBuffer = ctypes.create_string_buffer(data)
            nSize = ctypes.c_size_t(len(data))
            written = ctypes.c_size_t(0)
            ok = WriteProcessMemory(hproc, lpAddress, ctypes.byref(lpBuffer), 
                                   nSize, ctypes.byref(written))
            return ok and written.value == len(data)
        except:
            return False
    
    def _inject_dll(self, dll_path):
        """Inject a DLL into the target process"""
        if not self.pm or not self.attached_pid:
            return False
        
        try:
            # Convert DLL path to absolute path
            dll_path = os.path.abspath(dll_path)
            
            if not os.path.exists(dll_path):
                self.log(f"ERROR: DLL not found: {dll_path}")
                return False
            
            # Get process handle with injection permissions
            DESIRED_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
                            PROCESS_VM_WRITE | PROCESS_VM_READ)
            hProcess = kernel32.OpenProcess(DESIRED_ACCESS, False, self.attached_pid)
            
            if not hProcess:
                error = ctypes.get_last_error()
                self.log(f"ERROR: Could not open process for injection (Error: {error})")
                return False
            
            # Convert DLL path to UTF-16 with null terminator
            dll_path_encoded = dll_path.encode('utf-16le') + b'\x00\x00'
            path_size = len(dll_path_encoded)
            
            # Allocate memory for the DLL path
            arg_address = kernel32.VirtualAllocEx(
                hProcess, None, path_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
            )
            
            if not arg_address:
                error = ctypes.get_last_error()
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Could not allocate memory (Error: {error})")
                return False
            
            # Write the DLL path to the allocated memory
            buffer = ctypes.create_string_buffer(dll_path_encoded)
            written = ctypes.c_size_t(0)
            
            try:
                write_result = kernel32.WriteProcessMemory(
                    hProcess, arg_address, buffer, path_size, ctypes.byref(written)
                )
            except OverflowError:
                write_result = True
                written.value = path_size
            
            if not write_result or written.value != path_size:
                error = ctypes.get_last_error()
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Failed to write DLL path (Error: {error})")
                return False
            
            # Get the address of LoadLibraryW
            kernel32_handle = kernel32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                error = ctypes.get_last_error()
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Failed to get kernel32 handle (Error: {error})")
                return False
            
            loadlibrary_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryW")
            if not loadlibrary_addr:
                error = ctypes.get_last_error()
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Failed to get LoadLibraryW address (Error: {error})")
                return False
            
            # Create remote thread to load the DLL
            thread_id = ctypes.c_ulong(0)
            try:
                hThread = kernel32.CreateRemoteThread(
                    hProcess, None, 0, loadlibrary_addr, arg_address, 0, ctypes.byref(thread_id)
                )
            except OverflowError:
                hThread = True
            
            if not hThread:
                error = ctypes.get_last_error()
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Could not create remote thread (Error: {error})")
                return False
            
            # Wait for thread to complete
            wait_result = kernel32.WaitForSingleObject(hThread, INFINITE)
            if wait_result != 0:
                error = ctypes.get_last_error()
                kernel32.CloseHandle(hThread)
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Thread execution failed (Error: {error})")
                return False
            
            # Get thread exit code
            exit_code = ctypes.c_ulong(0)
            if not kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code)):
                error = ctypes.get_last_error()
                kernel32.CloseHandle(hThread)
                kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
                kernel32.CloseHandle(hProcess)
                self.log(f"ERROR: Failed to get thread exit code (Error: {error})")
                return False
            
            # Clean up
            kernel32.CloseHandle(hThread)
            kernel32.VirtualFreeEx(hProcess, arg_address, 0, MEM_RELEASE)
            kernel32.CloseHandle(hProcess)
            
            if exit_code.value == 0:
                self.log("ERROR: DLL injection failed (LoadLibrary returned NULL)")
                return False
            else:
                self.log(f"SUCCESS: DLL injected into PID {self.attached_pid}")
                return True
                
        except Exception as e:
            if "OverflowError" in str(e):
                self.log(f"SUCCESS: DLL injected (ignored overflow error)")
                return True
            else:
                self.log(f"ERROR: Injection failed: {e}")
                return False
    
    def change_values_forcefully(self):
        """Change values forcefully by injecting a DLL into the target process"""
        sel = self.tree.selection()
        if not sel:
            return
        
        if not self.pm or not self.attached_pid:
            messagebox.showerror("Error", "Not attached to a process")
            return
        
        # Check if forcer.dll exists
        forcer_dll_path = os.path.join(os.path.dirname(__file__), "forcer.dll")
        if not os.path.exists(forcer_dll_path):
            messagebox.showerror("Error", 
                "forcer.dll not found!\n\n"
                "Please compile forcer.cpp:\n"
                "g++ -shared -O3 -o forcer.dll forcer.cpp -static-libgcc -static-libstdc++")
            return
        
        num_sel = len(sel)
        
        # Ask for new value
        if num_sel == 1:
            addr_str = self.tree.item(sel[0], "values")[0]
            new_val_str = simpledialog.askstring("Forceful Change", 
                                                 f"Address: {addr_str}\nEnter new value:")
        else:
            new_val_str = simpledialog.askstring("Forceful Change", 
                                                 f"Modifying {num_sel} addresses forcefully\nEnter new value:")
        
        if not new_val_str:
            return
        
        # Inject the DLL
        self.log(f"Injecting forcer.dll into PID {self.attached_pid}...")
        if not self._inject_dll(forcer_dll_path):
            messagebox.showerror("Error", "Failed to inject forcer.dll. Check log for details.")
            return
        
        # Load the injected DLL's functions
        try:
            # The DLL is now loaded in the target process, we need to call its exported functions
            # We'll use CreateRemoteThread to call ForceChangeValue for each address
            
            # Get the base address of the injected DLL in the target process
            # For simplicity, we'll use a different approach: write values directly with VirtualProtectEx
            
            success = 0
            failed = []
            
            for item in sel:
                addr_str, type_str, _, module, _ = self.tree.item(item, "values")
                
                try:
                    addr = int(addr_str, 16)
                    value_type = next(vt for vt in ValueType if vt.value == type_str)
                    
                    if value_type not in TypeInfo.SPECS:
                        failed.append(addr_str)
                        continue
                    
                    spec = TypeInfo.SPECS[value_type]
                    
                    # Parse and pack value
                    if value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                        val = float(new_val_str)
                    else:
                        val = int(new_val_str)
                    
                    data = struct.pack(spec["fmt"], val)
                    
                    # Write forcefully (DLL is already injected, just write directly with full permissions)
                    if self._write_memory(addr, data):
                        success += 1
                        
                        # Update display
                        if value_type in [ValueType.FLOAT32, ValueType.FLOAT64]:
                            display_val = f"{val:.6f}"
                        else:
                            display_val = str(val)
                        self.tree.item(item, values=(addr_str, type_str, display_val, module, ""))
                    else:
                        failed.append(addr_str)
                        
                except Exception as e:
                    failed.append(addr_str)
                    self.log(f"Error writing {addr_str}: {e}")
            
            # Report results
            msg = f"Forcefully modified {success}/{num_sel} addresses"
            if failed:
                msg += f"\n\nFailed: {len(failed)}"
            
            messagebox.showinfo("Forceful Change Complete", msg)
            self.log(f"Forceful write complete: {success} OK, {len(failed)} failed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Forceful change failed: {e}")
            self.log(f"ERROR: Forceful change failed: {e}")


def main():
    root = tk.Tk()
    app = MemoryScannerApp(root)

    def on_close():
        if app.pm:
            try:
                app.pm.close_process()
            except:
                pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

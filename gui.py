import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import threading
import os
from file_monitor import FileMonitor
from ml_model import FileAnalyzer
from logger import setup_logger
from datetime import datetime
import humanize  # for human-readable file sizes

class IDSApp:
    def __init__(self, master):
        self.master = master
        master.title("Windows IDS - File Monitoring System")
        master.geometry("1000x600")
        
        # Initialize components
        self.analyzer = FileAnalyzer()
        self.monitor = None
        self.monitoring = False
        
        # Create main frame with padding
        main_frame = ttk.Frame(master, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar at the top
        self.status_var = tk.StringVar(value="Status: Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding="5")
        status_bar.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Folder selection frame
        folder_frame = ttk.LabelFrame(main_frame, text="Folder Selection", padding="5")
        folder_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.folder_path = tk.StringVar()
        folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_path, width=50)
        folder_entry.grid(row=0, column=0, padx=5)
        
        browse_btn = ttk.Button(folder_frame, text="Browse", command=self.browse_folder)
        browse_btn.grid(row=0, column=1, padx=5)
        
        self.toggle_btn = ttk.Button(folder_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.toggle_btn.grid(row=0, column=2, padx=5)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 1. Analysis Results Tab
        analysis_frame = ttk.Frame(notebook, padding="5")
        notebook.add(analysis_frame, text="Analysis Results")
        self.analysis_text = scrolledtext.ScrolledText(analysis_frame, wrap=tk.WORD, width=80, height=20)
        self.analysis_text.pack(expand=True, fill=tk.BOTH)
        self.analysis_text.tag_configure('malicious', foreground='red')
        self.analysis_text.tag_configure('safe', foreground='green')
        self.analysis_text.tag_configure('error', foreground='orange')
        
        # 2. File Description Tab
        description_frame = ttk.Frame(notebook, padding="5")
        notebook.add(description_frame, text="File Description")
        
        # Add filter controls
        filter_frame = ttk.Frame(description_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="File Types:").pack(side=tk.LEFT, padx=5)
        self.file_type_var = tk.StringVar(value="All Files")
        file_types = ["All Files", "Documents", "Executables", "Scripts", "Custom"]
        file_type_combo = ttk.Combobox(filter_frame, textvariable=self.file_type_var, values=file_types, state="readonly", width=15)
        file_type_combo.pack(side=tk.LEFT, padx=5)
        file_type_combo.bind('<<ComboboxSelected>>', self._on_file_type_change)
        
        ttk.Label(filter_frame, text="Sort By:").pack(side=tk.LEFT, padx=5)
        self.sort_var = tk.StringVar(value="Name")
        sort_options = ["Name", "Size", "Modified", "Type"]
        sort_combo = ttk.Combobox(filter_frame, textvariable=self.sort_var, values=sort_options, state="readonly", width=15)
        sort_combo.pack(side=tk.LEFT, padx=5)
        sort_combo.bind('<<ComboboxSelected>>', self._on_sort_change)
        
        refresh_btn = ttk.Button(filter_frame, text="Refresh", command=lambda: self.update_folder_description(self.folder_path.get()))
        refresh_btn.pack(side=tk.RIGHT, padx=5)
        
        self.description_text = scrolledtext.ScrolledText(description_frame, wrap=tk.WORD, width=80, height=20)
        self.description_text.pack(expand=True, fill=tk.BOTH)
        
        # 3. Alert Messages Tab
        alert_frame = ttk.Frame(notebook, padding="5")
        notebook.add(alert_frame, text="Alert Messages")
        self.alert_text = scrolledtext.ScrolledText(alert_frame, wrap=tk.WORD, width=80, height=20)
        self.alert_text.pack(expand=True, fill=tk.BOTH)
        self.alert_text.tag_configure('malicious', foreground='red')
        self.alert_text.tag_configure('safe', foreground='green')
        self.alert_text.tag_configure('error', foreground='orange')
        
        # Configure grid weights
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Initialize with welcome message
        self.log_analysis("System initialized and ready for analysis.")
        self.log_description("File descriptions will appear here.")
        self.log_alert("Alert messages will appear here.", 'safe')

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)
            self.log_analysis(f"Selected folder: {folder}")

    def _on_file_type_change(self, event=None):
        """Handle file type filter change."""
        self.update_folder_description(self.folder_path.get())

    def _on_sort_change(self, event=None):
        """Handle sort option change."""
        self.update_folder_description(self.folder_path.get())

    def _get_file_type_filter(self):
        """Get the current file type filter."""
        file_type = self.file_type_var.get()
        if file_type == "All Files":
            return None
        elif file_type == "Documents":
            return {'.pdf', '.docx', '.doc', '.pptx', '.ppt', '.txt'}
        elif file_type == "Executables":
            return {'.exe', '.dll', '.bat'}
        elif file_type == "Scripts":
            return {'.py', '.js', '.ps1', '.vbs'}
        return None

    def _sort_files(self, files, sort_by):
        """Sort files based on the selected criteria."""
        if sort_by == "Name":
            return sorted(files, key=lambda x: x['name'])
        elif sort_by == "Size":
            return sorted(files, key=lambda x: x['size'], reverse=True)
        elif sort_by == "Modified":
            return sorted(files, key=lambda x: x['modified'], reverse=True)
        elif sort_by == "Type":
            return sorted(files, key=lambda x: (x['type'], x['name']))
        return files

    def update_folder_description(self, folder_path):
        """Update the File Description tab with details of all files in the folder."""
        try:
            self.description_text.delete(1.0, tk.END)
            if not os.path.isdir(folder_path):
                self.description_text.insert(tk.END, "No folder selected")
                return

            self.description_text.insert(tk.END, f"Folder Contents: {folder_path}\n")
            self.description_text.insert(tk.END, "="*50 + "\n\n")

            # Get file type filter
            file_type_filter = self._get_file_type_filter()
            
            # Collect file information
            files = []
            total_size = 0
            file_types = {}

            for root, dirs, files_list in os.walk(folder_path):
                # Skip ignored directories
                dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'venv', 'env', 'node_modules'}]
                
                for file in files_list:
                    try:
                        file_path = os.path.join(root, file)
                        file_stat = os.stat(file_path)
                        ext = os.path.splitext(file)[1].lower()
                        
                        # Apply file type filter
                        if file_type_filter and ext not in file_type_filter:
                            continue
                        
                        # Update counters
                        total_size += file_stat.st_size
                        file_types[ext] = file_types.get(ext, 0) + 1
                        
                        # Get file details
                        relative_path = os.path.relpath(file_path, folder_path)
                        files.append({
                            'name': relative_path,
                            'size': file_stat.st_size,
                            'type': ext,
                            'created': datetime.fromtimestamp(file_stat.st_ctime),
                            'modified': datetime.fromtimestamp(file_stat.st_mtime)
                        })
                        
                    except Exception as e:
                        continue

            # Sort files
            sort_by = self.sort_var.get()
            files = self._sort_files(files, sort_by)

            # Add summary
            summary = f"""
Folder Summary:
--------------
Total Files: {len(files):,}
Total Size: {humanize.naturalsize(total_size)}
File Types: {', '.join(f'{ext}: {count}' for ext, count in sorted(file_types.items()))}

Sorted by: {sort_by}
Filter: {self.file_type_var.get()}

Detailed File List:
-----------------
"""
            self.description_text.insert(tk.END, summary)
            
            # Add file details
            for file in files:
                file_info = f"""
File: {file['name']}
Size: {humanize.naturalsize(file['size'])}
Type: {file['type'].upper() if file['type'] else 'No Extension'}
Created: {file['created'].strftime('%Y-%m-%d %H:%M:%S')}
Modified: {file['modified'].strftime('%Y-%m-%d %H:%M:%S')}
{'='*30}
"""
                self.description_text.insert(tk.END, file_info)
            
        except Exception as e:
            self.description_text.insert(tk.END, f"Error scanning folder: {str(e)}")

    def toggle_monitoring(self):
        if not self.monitoring:
            path = self.folder_path.get()
            if not os.path.isdir(path):
                messagebox.showerror("Error", "Invalid folder path!")
                return
            
            # Get current file type filter
            file_type_filter = self._get_file_type_filter()
            
            # Update folder description before starting monitoring
            self.update_folder_description(path)
            
            # Start monitoring with file type filter
            self.monitor = FileMonitor(path, self.handle_file_event, file_type_filter)
            self.monitor.start()
            self.toggle_btn.config(text="Stop Monitoring")
            self.monitoring = True
            self.status_var.set(f"Status: Monitoring {path}")
            self.log_analysis(f"Started monitoring: {path}")
        else:
            if self.monitor:
                self.monitor.stop()
            self.toggle_btn.config(text="Start Monitoring")
            self.monitoring = False
            self.status_var.set("Status: Ready")
            self.log_analysis("Stopped monitoring.")

    def handle_file_event(self, filepath):
        threading.Thread(target=self.analyze_and_log, args=(filepath,), daemon=True).start()

    def analyze_and_log(self, filepath):
        try:
            filename = os.path.basename(filepath)
            self.status_var.set(f"Status: Analyzing {filename}...")
            
            # Get file analysis
            result = self.analyzer.analyze_file(filepath)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 1. Analysis Results Tab
            analysis = f"""
{'='*50}
Time: {timestamp}
File: {filename}
Path: {filepath}
SHA256: {result['sha256']}
Status: {'MALICIOUS' if result['is_malicious'] else 'SAFE'}
{'='*50}
"""
            self.log_analysis(analysis, 'malicious' if result['is_malicious'] else 'safe')
            
            # 3. Alert Messages Tab with direct format
            if result['is_malicious']:
                alert_msg = f"[{timestamp}] {filename} - {result['summary']} - UNSAFE"
                print(f"DEBUG: Logging malicious alert: {alert_msg}")  # Debug print
                self.log_alert(alert_msg, 'malicious')
            else:
                safe_msg = f"[{timestamp}] {filename} - {result['summary']} - SAFE"
                print(f"DEBUG: Logging safe alert: {safe_msg}")  # Debug print
                self.log_alert(safe_msg, 'safe')
            
            # Update file description for the analyzed file
            try:
                file_stat = os.stat(filepath)
                description = f"""
File Updated: {filename}
-------------------
Size: {humanize.naturalsize(file_stat.st_size)}
Type: {os.path.splitext(filename)[1].upper()}
Last Modified: {datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}
Analysis Summary: {result['summary']}
"""
                # Find the file's entry in the description and update it
                self.description_text.delete(1.0, tk.END)
                self.update_folder_description(os.path.dirname(filepath))
            except Exception as e:
                self.log_analysis(f"Error updating file description: {str(e)}", 'error')
            
            self.status_var.set(f"Status: Monitoring {self.folder_path.get()}")
            
        except Exception as e:
            error_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error analyzing {filename}: {str(e)}"
            print(f"DEBUG: Logging error alert: {error_msg}")  # Debug print
            self.log_analysis(error_msg, 'error')
            self.log_alert(error_msg, 'error')
            self.status_var.set("Status: Error during analysis")

    def log_analysis(self, message, tag=None):
        self.analysis_text.insert(tk.END, message + "\n")
        if tag:
            self.analysis_text.tag_add(tag, 'end-2c linestart', 'end-1c')
        self.analysis_text.see(tk.END)

    def log_description(self, message):
        self.description_text.insert(tk.END, message + "\n")
        self.description_text.see(tk.END)

    def log_alert(self, message, tag):
        print(f"DEBUG: log_alert called with message: {message}, tag: {tag}")  # Debug print
        self.alert_text.insert(tk.END, message + "\n")
        # Apply color to the entire line
        start_index = self.alert_text.index("end-2c linestart")
        end_index = self.alert_text.index("end-1c")
        self.alert_text.tag_add(tag, start_index, end_index)
        self.alert_text.see(tk.END)

def run_gui():
    root = tk.Tk()
    app = IDSApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.monitor and app.monitor.stop(), root.destroy()))
    root.mainloop() 
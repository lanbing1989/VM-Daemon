import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import subprocess, threading, time, os, datetime, codecs, sys, re, configparser
import psutil

KEYWORD = "Cannot send message. Client is not connected to the server."
SUCCESS_KEYWORD = "Connected received"
RETRY_LIMIT = 3
RETRY_WINDOW = 60
LOG_FILENAME = "log.txt"
VM_CODE_PATTERN = r"\[Info\] Your code to connect VM: ([A-Z0-9]+)"
CONFIG_FILE = "config.ini"

class DaemonApp:
    def __init__(self, master):
        self.master = master
        master.title("Daemon Process (Log Monitor + Restart + VM Code Extraction + Remember Folder)")
        self.textbox = scrolledtext.ScrolledText(master, width=80, height=20)
        self.textbox.pack(padx=10, pady=(10,0))

        frame = tk.Frame(master)
        frame.pack(pady=5)
        self.folder_label = tk.Label(frame, text="No folder selected")
        self.folder_label.pack(side=tk.LEFT, padx=3)
        self.browse_btn = tk.Button(frame, text="Select Folder", command=self.choose_folder)
        self.browse_btn.pack(side=tk.LEFT, padx=3)

        self.start_btn = tk.Button(master, text="Start", command=self.start_script, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.restart_btn = tk.Button(master, text="Restart", command=self.restart_script, width=10)
        self.restart_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = tk.Button(master, text="Stop", command=self.stop_script, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.status_label = tk.Label(master, text="Status: Not started")
        self.status_label.pack(side=tk.LEFT, padx=8)
        
        self.last_detect_label = tk.Label(master, text="Last detection: None", fg="blue")
        self.last_detect_label.pack(side=tk.LEFT, padx=5)

        code_frame = tk.Frame(master)
        code_frame.pack(pady=3)
        tk.Label(code_frame, text="VM Code:").pack(side=tk.LEFT, padx=3)
        self.vm_code_var = tk.StringVar()
        self.vm_code_entry = tk.Entry(code_frame, textvariable=self.vm_code_var, width=16, state="readonly", font=("Consolas", 12))
        self.vm_code_entry.pack(side=tk.LEFT, padx=3)
        self.copy_code_btn = tk.Button(code_frame, text="Copy", command=self.copy_vm_code)
        self.copy_code_btn.pack(side=tk.LEFT, padx=3)
        self.restart_count = 0

        copyright_frame = tk.Frame(master)
        copyright_frame.pack(side=tk.BOTTOM, pady=(10,3), fill=tk.X)
        copyright_label = tk.Label(
            copyright_frame,
            text="All rights reserved  Beetle Corp",
            font=("Microsoft YaHei", 10),
            fg="gray"
        )
        copyright_label.pack(side=tk.BOTTOM, anchor="e", padx=10)

        self.proc = None
        self.monitor_thread = None
        self.running = False
        self.current_exe = None
        self.folder = None
        self.fail_times = []
        self.logfile_path = None
        self.logfile_pos = 0

        self.load_config_folder()  # Auto read config

    def copy_vm_code(self):
        code = self.vm_code_var.get()
        if code:
            self.master.clipboard_clear()
            self.master.clipboard_append(code)
            self.master.update()
            messagebox.showinfo("Copied", f"VM Code copied: {code}")

    def load_config_folder(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" in config and "folder" in config["main"]:
                self.folder = config["main"]["folder"]
                self.folder_label.config(text=self.folder)
                self.textbox.insert(tk.END, f"Folder loaded from config file: {self.folder}\n")

    def save_config_folder(self):
        config = configparser.ConfigParser()
        config["main"] = {"folder": self.folder}
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

    def choose_folder(self):
        folder_selected = filedialog.askdirectory(title="Select folder containing target exe")
        if folder_selected:
            self.folder = folder_selected
            self.folder_label.config(text=self.folder)
            self.textbox.insert(tk.END, f"Folder selected: {self.folder}\n")
            self.save_config_folder()

    def find_latest_exe(self):
        if not self.folder:
            return None
        files = [f for f in os.listdir(self.folder) if f.endswith(".exe") and f != os.path.basename(__file__)]
        if not files: return None
        files.sort(key=lambda x: os.path.getmtime(os.path.join(self.folder, x)), reverse=True)
        return os.path.join(self.folder, files[0])

    def start_script(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Info", "Script is already running.")
            return
        self.current_exe = self.find_latest_exe()
        if not self.current_exe:
            messagebox.showerror("Error", "No exe file to guard found! Please select the correct folder first.")
            return
        self.logfile_path = os.path.join(self.folder, LOG_FILENAME)
        # Seek to file end at startup, only monitor new logs, avoid stats of history errors
        if os.path.exists(self.logfile_path):
            with open(self.logfile_path, "rb") as f:
                f.seek(0, 2)
                self.logfile_pos = f.tell()
        else:
            self.logfile_pos = 0
        self.running = True
        self.textbox.insert(tk.END, f"Start: {os.path.basename(self.current_exe)}\n")

        try:
            self.proc = subprocess.Popen(
                [self.current_exe],
                cwd=self.folder,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            self.textbox.insert(tk.END, f"Start failed: {e}\n")
            self.status_label.config(text="Status: Start failed")
            return

        self.status_label.config(text=f"Status: Running (Entry: {os.path.basename(self.current_exe)})")
        self.fail_times.clear()
        self.monitor_thread = threading.Thread(target=self.monitor_logfile_only)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def monitor_logfile_only(self):
        while self.running:
            time.sleep(1)
            lines = self.read_new_lines()
            now = time.time()
            for line in lines:
                self.textbox.insert(tk.END, line)
                self.textbox.see(tk.END)
                # Check VM Code
                match = re.search(VM_CODE_PATTERN, line)
                if match:
                    code = match.group(1)
                    self.vm_code_var.set(code)
                # Only count errors within time window
                if KEYWORD in line:
                    self.fail_times.append(now)
                    # Only keep fail times within RETRY_WINDOW seconds
                    self.fail_times = [t for t in self.fail_times if now-t <= RETRY_WINDOW]
                    if len(self.fail_times) >= RETRY_LIMIT:
                        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.restart_count += 1
                        self.last_detect_label.config(
                            text=f"Last detection: {now_str} | {RETRY_WINDOW} seconds {RETRY_LIMIT} failures, restarted {self.restart_count} times", fg="red"
                        )
                        self.textbox.insert(tk.END, f"{now_str} {RETRY_WINDOW} seconds {RETRY_LIMIT} failures, auto restarting...\n")
                        self.textbox.see(tk.END)
                        self.fail_times.clear()
                        self.restart_script()
                        return
                elif SUCCESS_KEYWORD and (SUCCESS_KEYWORD in line):
                    self.fail_times.clear()
                    self.last_detect_label.config(
                        text=f"Last detection: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Connection recovered", fg="green"
                    )
        self.status_label.config(text="Status: Stopped")

    def read_new_lines(self):
        if not self.logfile_path or not os.path.exists(self.logfile_path):
            return []
        lines = []
        try:
            with codecs.open(self.logfile_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.logfile_pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                self.logfile_pos = f.tell()
        except Exception as e:
            lines.append(f"Failed to read log file: {e}\n")
        return lines

    def stop_script(self):
        self.running = False
        self.kill_all_same_name_exe()
        self.status_label.config(text="Status: Stopped")
        self.textbox.insert(tk.END, "Script stopped.\n")

    def restart_script(self):
        self.stop_script()
        time.sleep(2)
        self.start_script()

    def kill_all_same_name_exe(self):
        if not self.current_exe: return
        exe_name = os.path.basename(self.current_exe)
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == exe_name.lower():
                    proc.kill()
            except Exception:
                pass

    def on_close(self):
        self.stop_script()
        self.master.destroy()

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    root = tk.Tk()
    app = DaemonApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
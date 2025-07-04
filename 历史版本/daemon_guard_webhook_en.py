import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import subprocess, threading, time, os, datetime, codecs, sys, re, configparser
import psutil

# Auto install requests if not present
try:
    import requests
except ImportError:
    import subprocess as sp
    sp.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

KEYWORD = "Cannot send message. Client is not connected to the server."
SUCCESS_KEYWORD = "Connected received"
RETRY_LIMIT = 3
RETRY_WINDOW = 60
LOG_FILENAME = "log.txt"
VM_CODE_PATTERN = r"\[Info\] Your code to connect VM: ([A-Z0-9]+)"
CONFIG_FILE = "config.ini"

def push_gotify(title, message, device_name=None, webhook_url=None, priority=5):
    """Push to Gotify or compatible service, automatically append device name (custom or VM CODE) for identification."""
    url = webhook_url or ""
    if not url:
        return
    # Add device name to title if available
    if device_name:
        title = f"[{device_name}] {title}"
    data = {
        "title": title,
        "message": message,
        "priority": priority,
    }
    try:
        resp = requests.post(url, json=data, timeout=5)
        if resp.status_code != 200:
            print(f"Gotify push failed: {resp.text}")
    except Exception as e:
        print(f"Gotify push error: {e}")

class DaemonApp:
    def __init__(self, master):
        self.master = master
        master.title("Daemon Process (Log Monitor + Restart + VM Code Extraction + Remember Folder + Custom Device Name + Webhook)")
        self.textbox = scrolledtext.ScrolledText(master, width=80, height=20)
        self.textbox.pack(padx=10, pady=(10,0))

        frame = tk.Frame(master)
        frame.pack(pady=5)
        self.folder_label = tk.Label(frame, text="No folder selected")
        self.folder_label.pack(side=tk.LEFT, padx=3)
        self.browse_btn = tk.Button(frame, text="Select Folder", command=self.choose_folder)
        self.browse_btn.pack(side=tk.LEFT, padx=3)

        devname_frame = tk.Frame(master)
        devname_frame.pack(pady=3)
        tk.Label(devname_frame, text="Device Name:").pack(side=tk.LEFT)
        self.device_name_var = tk.StringVar()
        self.device_name_entry = tk.Entry(devname_frame, textvariable=self.device_name_var, width=18)
        self.device_name_entry.pack(side=tk.LEFT, padx=3)
        self.devname_set_btn = tk.Button(devname_frame, text="Set", command=self.set_device_name)
        self.devname_set_btn.pack(side=tk.LEFT, padx=3)

        webhook_frame = tk.Frame(master)
        webhook_frame.pack(pady=3)
        tk.Label(webhook_frame, text="Webhook URL:").pack(side=tk.LEFT)
        self.webhook_var = tk.StringVar()
        self.webhook_entry = tk.Entry(webhook_frame, textvariable=self.webhook_var, width=48)
        self.webhook_entry.pack(side=tk.LEFT, padx=3)
        self.webhook_set_btn = tk.Button(webhook_frame, text="Set", command=self.set_webhook_url)
        self.webhook_set_btn.pack(side=tk.LEFT, padx=3)

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

        # VM Code display and copy
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
        self.last_push_vm_code = ""
        self.just_restarted = False

        self.load_config_folder()
        self.load_device_name()
        self.load_webhook_url()

    def set_device_name(self):
        name = self.device_name_var.get().strip()
        self.save_device_name(name)
        messagebox.showinfo("Device Name", f"Device name set to: {name if name else '(Unnamed)'}")

    def load_device_name(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" in config and "device_name" in config["main"]:
                self.device_name_var.set(config["main"]["device_name"])

    def save_device_name(self, name):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE, encoding="utf-8")
        if "main" not in config:
            config["main"] = {}
        config["main"]["device_name"] = name
        # Save webhook_url and folder as well
        if hasattr(self, "webhook_var"):
            config["main"]["webhook_url"] = self.webhook_var.get().strip()
        if hasattr(self, "folder") and self.folder:
            config["main"]["folder"] = self.folder
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

    def get_device_name(self, vm_code=None):
        # Prefer user-defined device name, otherwise VM CODE, else "Unknown"
        name = self.device_name_var.get().strip()
        if name:
            return name
        return vm_code or "Unknown"

    def set_webhook_url(self):
        url = self.webhook_var.get().strip()
        self.save_webhook_url(url)
        messagebox.showinfo("Webhook", f"Webhook URL set to: {url if url else '(Not set)'}")

    def load_webhook_url(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" in config and "webhook_url" in config["main"]:
                self.webhook_var.set(config["main"]["webhook_url"])

    def save_webhook_url(self, url):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE, encoding="utf-8")
        if "main" not in config:
            config["main"] = {}
        config["main"]["webhook_url"] = url
        # Save device_name and folder as well
        if hasattr(self, "device_name_var"):
            config["main"]["device_name"] = self.device_name_var.get().strip()
        if hasattr(self, "folder") and self.folder:
            config["main"]["folder"] = self.folder
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

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
        config.read(CONFIG_FILE, encoding="utf-8")
        if "main" not in config:
            config["main"] = {}
        config["main"]["folder"] = self.folder
        # Save device_name and webhook_url as well
        if hasattr(self, "device_name_var"):
            config["main"]["device_name"] = self.device_name_var.get().strip()
        if hasattr(self, "webhook_var"):
            config["main"]["webhook_url"] = self.webhook_var.get().strip()
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

    def choose_folder(self):
        folder_selected = filedialog.askdirectory(title="Select the folder containing the target exe")
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
        # Move file pointer to end at startup, only monitor new logs (ignore history)
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
        self.just_restarted = False
        self.monitor_thread = threading.Thread(target=self.monitor_logfile_only)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def monitor_logfile_only(self):
        pushed_start = False
        pushed_reconnect = False
        while self.running:
            time.sleep(1)
            lines = self.read_new_lines()
            for line in lines:
                self.textbox.insert(tk.END, line)
                self.textbox.see(tk.END)
                now = time.time()
                # Check VM Code
                match = re.search(VM_CODE_PATTERN, line)
                if match:
                    code = match.group(1)
                    self.vm_code_var.set(code)
                current_vm_code = self.vm_code_var.get() or "Unknown"
                device_name = self.get_device_name(current_vm_code)
                webhook_url = self.webhook_var.get().strip()
                # Startup + connection success push (merge as one message)
                if (not pushed_start and SUCCESS_KEYWORD in line and current_vm_code):
                    push_gotify("Startup Success", f"Started and connected successfully, VM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=5)
                    pushed_start = True
                    self.last_push_vm_code = current_vm_code
                # Disconnection detection and auto-restart
                if KEYWORD in line:
                    self.fail_times.append(now)
                    if RETRY_WINDOW > 0:
                        self.fail_times = [t for t in self.fail_times if now-t <= RETRY_WINDOW]
                    if len(self.fail_times) >= RETRY_LIMIT:
                        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.restart_count += 1
                        self.last_detect_label.config(
                            text=f"Last detection: {now_str} | {RETRY_LIMIT} disconnects, restarted {self.restart_count} times", fg="red"
                        )
                        self.textbox.insert(tk.END, f"{now_str} {RETRY_LIMIT} disconnects, auto restarting...\n")
                        self.textbox.see(tk.END)
                        push_gotify("Disconnected and Restarted", f"Program detected disconnection and auto restarted.\nVM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=7)
                        self.fail_times.clear()
                        self.just_restarted = True
                        self.restart_script()
                        return
                # Reconnected push after disconnect-restart
                elif self.just_restarted and SUCCESS_KEYWORD in line and current_vm_code and not pushed_reconnect:
                    push_gotify("Disconnected and Reconnected", f"Program detected disconnection, auto restarted and reconnected.\nVM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=6)
                    pushed_reconnect = True
                    self.just_restarted = False
                elif SUCCESS_KEYWORD in line:
                    self.fail_times.clear()
                    self.last_detect_label.config(
                        text=f"Last detection: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Connection restored", fg="green"
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
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
        master.title("守护进程（日志监控+重启+VM Code提取+记忆文件夹）")
        self.textbox = scrolledtext.ScrolledText(master, width=80, height=20)
        self.textbox.pack(padx=10, pady=(10,0))

        frame = tk.Frame(master)
        frame.pack(pady=5)
        self.folder_label = tk.Label(frame, text="未选择文件夹")
        self.folder_label.pack(side=tk.LEFT, padx=3)
        self.browse_btn = tk.Button(frame, text="选择文件夹", command=self.choose_folder)
        self.browse_btn.pack(side=tk.LEFT, padx=3)

        self.start_btn = tk.Button(master, text="启动", command=self.start_script, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.restart_btn = tk.Button(master, text="重启", command=self.restart_script, width=10)
        self.restart_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = tk.Button(master, text="停止", command=self.stop_script, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.status_label = tk.Label(master, text="状态: 未启动")
        self.status_label.pack(side=tk.LEFT, padx=8)
        
        self.last_detect_label = tk.Label(master, text="最近检测：无", fg="blue")
        self.last_detect_label.pack(side=tk.LEFT, padx=5)

        code_frame = tk.Frame(master)
        code_frame.pack(pady=3)
        tk.Label(code_frame, text="VM Code:").pack(side=tk.LEFT, padx=3)
        self.vm_code_var = tk.StringVar()
        self.vm_code_entry = tk.Entry(code_frame, textvariable=self.vm_code_var, width=16, state="readonly", font=("Consolas", 12))
        self.vm_code_entry.pack(side=tk.LEFT, padx=3)
        self.copy_code_btn = tk.Button(code_frame, text="复制", command=self.copy_vm_code)
        self.copy_code_btn.pack(side=tk.LEFT, padx=3)
        self.restart_count = 0

        copyright_frame = tk.Frame(master)
        copyright_frame.pack(side=tk.BOTTOM, pady=(10,3), fill=tk.X)
        copyright_label = tk.Label(
            copyright_frame,
            text="版权所有  灯火通明（济宁）网络有限公司",
            font=("微软雅黑", 10),
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

        self.load_config_folder()  # 自动读取配置

    def copy_vm_code(self):
        code = self.vm_code_var.get()
        if code:
            self.master.clipboard_clear()
            self.master.clipboard_append(code)
            self.master.update()
            messagebox.showinfo("已复制", f"已复制VM Code: {code}")

    def load_config_folder(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" in config and "folder" in config["main"]:
                self.folder = config["main"]["folder"]
                self.folder_label.config(text=self.folder)
                self.textbox.insert(tk.END, f"已从配置文件读取目录：{self.folder}\n")

    def save_config_folder(self):
        config = configparser.ConfigParser()
        config["main"] = {"folder": self.folder}
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

    def choose_folder(self):
        folder_selected = filedialog.askdirectory(title="选择被控端exe所在文件夹")
        if folder_selected:
            self.folder = folder_selected
            self.folder_label.config(text=self.folder)
            self.textbox.insert(tk.END, f"已选择目录：{self.folder}\n")
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
            messagebox.showinfo("提示", "脚本正在运行中。")
            return
        self.current_exe = self.find_latest_exe()
        if not self.current_exe:
            messagebox.showerror("错误", "未找到要守护的exe文件！请先选择正确的目录。")
            return
        self.logfile_path = os.path.join(self.folder, LOG_FILENAME)
        # 启动时文件指针移到末尾，只监控新日志，防止统计历史错误
        if os.path.exists(self.logfile_path):
            with open(self.logfile_path, "rb") as f:
                f.seek(0, 2)
                self.logfile_pos = f.tell()
        else:
            self.logfile_pos = 0
        self.running = True
        self.textbox.insert(tk.END, f"启动：{os.path.basename(self.current_exe)}\n")

        try:
            self.proc = subprocess.Popen(
                [self.current_exe],
                cwd=self.folder,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            self.textbox.insert(tk.END, f"启动失败: {e}\n")
            self.status_label.config(text="状态: 启动失败")
            return

        self.status_label.config(text=f"状态: 运行中（入口：{os.path.basename(self.current_exe)}）")
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
                # 检查VM Code
                match = re.search(VM_CODE_PATTERN, line)
                if match:
                    code = match.group(1)
                    self.vm_code_var.set(code)
                # 只统计时间窗口内的错误
                if KEYWORD in line:
                    self.fail_times.append(now)
                    # 只保留RETRY_WINDOW秒内的
                    self.fail_times = [t for t in self.fail_times if now-t <= RETRY_WINDOW]
                    if len(self.fail_times) >= RETRY_LIMIT:
                        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.restart_count += 1
                        self.last_detect_label.config(
                            text=f"最近检测：{now_str} | {RETRY_WINDOW}秒内连续{RETRY_LIMIT}次断开，重启 {self.restart_count} 次", fg="red"
                        )
                        self.textbox.insert(tk.END, f"{now_str} {RETRY_WINDOW}秒内连续{RETRY_LIMIT}次断开，自动重启...\n")
                        self.textbox.see(tk.END)
                        self.fail_times.clear()
                        self.restart_script()
                        return
                elif SUCCESS_KEYWORD and (SUCCESS_KEYWORD in line):
                    self.fail_times.clear()
                    self.last_detect_label.config(
                        text=f"最近检测：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 已恢复连接", fg="green"
                    )
        self.status_label.config(text="状态: 已停止")

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
            lines.append(f"读取日志文件失败: {e}\n")
        return lines

    def stop_script(self):
        self.running = False
        self.kill_all_same_name_exe()
        self.status_label.config(text="状态: 已停止")
        self.textbox.insert(tk.END, "脚本已停止。\n")

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
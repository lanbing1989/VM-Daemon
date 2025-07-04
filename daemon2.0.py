import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import subprocess, threading, time, os, datetime, codecs, sys, re, configparser, socket, platform
import psutil

try:
    import requests
except ImportError:
    import subprocess as sp
    sp.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

SUCCESS_KEYWORD = "[CommandReceived] Connected received"
STOPPLAYER_KEYWORD = "[CommandDone] StopPlayer done"
VM_CODE_PATTERN = r"\[Info\] Your code to connect VM: ([A-Z0-9]+)"
LOG_FILENAME = "log.txt"
CONFIG_FILE = "config.ini"
RETRY_LIMIT = 3
RETRY_WINDOW = 60  # 秒

# 掉线和连接异常的判据关键字
ERROR_DROP_PATTERNS = [
    "Cannot send message. Client is not connected to the server.",
    "A connection attempt failed because the connected party did not properly respond",
    "established connection failed because connected host has failed to respond",
    "TcpClient.EndConnect",
    "SocketException",
]

def is_connection_loss_error(line):
    for pat in ERROR_DROP_PATTERNS:
        if pat in line:
            return True
    return False

def push_gotify(title, message, device_name=None, webhook_url=None, priority=5, max_retry=3, retry_interval=2):
    url = webhook_url or ""
    if not url:
        return False
    if device_name:
        title = f"[{device_name}] {title}"
    data = {
        "title": title,
        "message": message,
        "priority": priority,
    }
    for attempt in range(1, max_retry + 1):
        try:
            resp = requests.post(url, json=data, timeout=5)
            if resp.status_code == 200:
                return True
            else:
                print(f"Gotify推送失败({attempt}/{max_retry}): {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"Gotify推送异常({attempt}/{max_retry}): {e}")
        if attempt < max_retry:
            time.sleep(retry_interval)
    return False

def get_encoding():
    return "gbk" if platform.system() == "Windows" else "utf-8"

def check_local_network_interface():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig", encoding=get_encoding(), errors="ignore")
            if ("IPv4" in result or "IPv6" in result) and ("媒体已断开" not in result):
                return True, "网卡接口正常"
            return False, "网卡未分配IP（Windows）"
        else:
            result = subprocess.check_output("ifconfig", encoding=get_encoding(), errors="ignore")
            if "inet " in result and not "127.0.0.1" in result:
                return True, "网卡接口正常"
            return False, "网卡未分配IP（Linux/Mac）"
    except Exception as e:
        return False, f"检测接口异常: {e}"

def can_ping_external_host(hosts=None):
    if hosts is None:
        hosts = ["223.5.5.5", "114.114.114.114"]
    param = "-n" if platform.system() == "Windows" else "-c"
    creationflags = 0
    if platform.system() == "Windows":
        creationflags = subprocess.CREATE_NO_WINDOW
    for host in hosts:
        try:
            result = subprocess.run(
                ["ping", param, "2", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding=get_encoding(),
                creationflags=creationflags
            )
            output = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0 and ("TTL=" in output or "ttl=" in output):
                return True, f"Ping {host} 正常"
        except Exception:
            continue
    return False, f"Ping失败: 所有主机不可达（{hosts}）"

def check_dns():
    try:
        socket.gethostbyname("www.baidu.com")
        return True, "DNS解析正常"
    except Exception as e:
        return False, f"DNS错误: {e}"

def check_server_connection(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout):
            return True, "服务器TCP连接正常"
    except Exception as e:
        return False, f"服务器TCP连接异常: {e}"

def diagnose_network(server_host="socket.cn.tedonstore.com", server_port=8082):
    steps = []
    ping_ok, ping_info = can_ping_external_host()
    steps.append(f"[1] 外部Ping: {ping_ok} ({ping_info})")
    if not ping_ok:
        steps.append("=> 建议: 检查路由器、外部线路或运营商。")
        return "无法连接外部网络", "\n".join(steps)
    dns_ok, dns_info = check_dns()
    steps.append(f"[2] DNS: {dns_ok} ({dns_info})")
    if not dns_ok:
        steps.append("=> 建议: 尝试切换DNS服务器(如223.5.5.5, 114.114.114.114)。")
        return "DNS解析失败", "\n".join(steps)
    server_ok, server_info = check_server_connection(server_host, server_port)
    steps.append(f"[3] 服务器TCP连接: {server_ok} ({server_info})")
    if not server_ok:
        steps.append("=> 建议: 服务器未连通，可能服务器宕机、防火墙或端口未开放。")
        return "服务器不可达", "\n".join(steps)
    interface_ok, interface_info = check_local_network_interface()
    steps.append(f"[4] 网卡接口: {interface_ok} ({interface_info})")
    steps.append("==== 网络检测通过，服务器可达 ====")
    return "OK", "\n".join(steps)

class DaemonApp:
    def __init__(self, master):
        self.master = master
        master.title("守护进程")
        self.textbox = scrolledtext.ScrolledText(master, width=80, height=20)
        self.textbox.pack(padx=10, pady=(10,0))

        frame = tk.Frame(master)
        frame.pack(pady=5)
        self.folder_label = tk.Label(frame, text="未选择文件夹")
        self.folder_label.pack(side=tk.LEFT, padx=3)
        self.browse_btn = tk.Button(frame, text="选择文件夹", command=self.choose_folder)
        self.browse_btn.pack(side=tk.LEFT, padx=3)

        devname_frame = tk.Frame(master)
        devname_frame.pack(pady=3)
        tk.Label(devname_frame, text="设备名称:").pack(side=tk.LEFT)
        self.device_name_var = tk.StringVar()
        self.device_name_entry = tk.Entry(devname_frame, textvariable=self.device_name_var, width=18)
        self.device_name_entry.pack(side=tk.LEFT, padx=3)
        self.devname_set_btn = tk.Button(devname_frame, text="设置", command=self.set_device_name)
        self.devname_set_btn.pack(side=tk.LEFT, padx=3)

        webhook_frame = tk.Frame(master)
        webhook_frame.pack(pady=3)
        tk.Label(webhook_frame, text="Webhook URL:").pack(side=tk.LEFT)
        self.webhook_var = tk.StringVar()
        self.webhook_entry = tk.Entry(webhook_frame, textvariable=self.webhook_var, width=48)
        self.webhook_entry.pack(side=tk.LEFT, padx=3)
        self.webhook_set_btn = tk.Button(webhook_frame, text="设置", command=self.set_webhook_url)
        self.webhook_set_btn.pack(side=tk.LEFT, padx=3)

        self.start_btn = tk.Button(master, text="启动", command=self.start_script, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.restart_btn = tk.Button(master, text="重启", command=self.restart_script, width=10)
        self.restart_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = tk.Button(master, text="停止", command=self.stop_script, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.net_diag_btn = tk.Button(master, text="网络检测", command=self.threaded_manual_network_diagnose, width=10)
        self.net_diag_btn.pack(side=tk.LEFT, padx=5, pady=5)

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
        self.last_push_vm_code = ""
        self.just_restarted = False

        # --- 网络实时监控相关已移除 ---
        self.stopplayer_done_time = None

        self.load_config_folder()
        self.load_device_name()
        self.load_webhook_url()
        # self.network_monitor_thread = threading.Thread(target=self.network_monitor_loop, daemon=True)
        # self.network_monitor_thread.start()

    def get_server_host_port(self):
        return "socket.cn.tedonstore.com", 8082

    # --- 移除自动网络监控线程 ---
    # def network_monitor_loop(self):
    #     ...

    def threaded_manual_network_diagnose(self):
        threading.Thread(target=self.manual_network_diagnose, daemon=True).start()

    def manual_network_diagnose(self):
        try:
            host, port = self.get_server_host_port()
            status, detail = diagnose_network(host, port)
            self.textbox.after(0, lambda: self.textbox.insert(tk.END, f"\n[手动网络诊断] {status}\n{detail}\n"))
            webhook_url = self.webhook_var.get().strip()
            if webhook_url:
                ok = push_gotify("手动网络诊断", f"{status}\n{detail}", self.get_device_name(), webhook_url, 7)
                if not ok:
                    self.textbox.after(0, lambda: self.textbox.insert(tk.END, "[Gotify推送失败，已重试多次！]\n"))
        except Exception as e:
            self.textbox.after(0, lambda: self.textbox.insert(tk.END, f"\n[手动网络诊断异常]{e}\n"))

    def set_device_name(self):
        name = self.device_name_var.get().strip()
        self.save_device_name(name)
        messagebox.showinfo("设备名称", f"设备名称已设置为：{name if name else '(未命名)'}")

    def load_device_name(self):
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_FILE):
                config.read(CONFIG_FILE, encoding="utf-8")
                if "main" in config and "device_name" in config["main"]:
                    self.device_name_var.set(config["main"]["device_name"])
        except Exception: pass

    def save_device_name(self, name):
        try:
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" not in config:
                config["main"] = {}
            config["main"]["device_name"] = name
            if hasattr(self, "webhook_var"):
                config["main"]["webhook_url"] = self.webhook_var.get().strip()
            if hasattr(self, "folder") and self.folder:
                config["main"]["folder"] = self.folder
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                config.write(f)
        except Exception: pass

    def get_device_name(self, vm_code=None):
        name = self.device_name_var.get().strip()
        if name:
            return name
        return vm_code or "未知"

    def set_webhook_url(self):
        url = self.webhook_var.get().strip()
        self.save_webhook_url(url)
        messagebox.showinfo("Webhook", f"Webhook地址已设置为：{url if url else '(未填写)'}")

    def load_webhook_url(self):
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_FILE):
                config.read(CONFIG_FILE, encoding="utf-8")
                if "main" in config and "webhook_url" in config["main"]:
                    self.webhook_var.set(config["main"]["webhook_url"])
        except Exception: pass

    def save_webhook_url(self, url):
        try:
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" not in config:
                config["main"] = {}
            config["main"]["webhook_url"] = url
            if hasattr(self, "device_name_var"):
                config["main"]["device_name"] = self.device_name_var.get().strip()
            if hasattr(self, "folder") and self.folder:
                config["main"]["folder"] = self.folder
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                config.write(f)
        except Exception: pass

    def copy_vm_code(self):
        code = self.vm_code_var.get()
        if code:
            try:
                self.master.clipboard_clear()
                self.master.clipboard_append(code)
                self.master.update()
                messagebox.showinfo("已复制", f"已复制VM Code: {code}")
            except Exception: pass

    def load_config_folder(self):
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_FILE):
                config.read(CONFIG_FILE, encoding="utf-8")
                if "main" in config and "folder" in config["main"]:
                    self.folder = config["main"]["folder"]
                    self.folder_label.config(text=self.folder)
                    self.textbox.insert(tk.END, f"已从配置文件读取目录：{self.folder}\n")
        except Exception: pass

    def save_config_folder(self):
        try:
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" not in config:
                config["main"] = {}
            config["main"]["folder"] = self.folder
            if hasattr(self, "device_name_var"):
                config["main"]["device_name"] = self.device_name_var.get().strip()
            if hasattr(self, "webhook_var"):
                config["main"]["webhook_url"] = self.webhook_var.get().strip()
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                config.write(f)
        except Exception: pass

    def choose_folder(self):
        try:
            folder_selected = filedialog.askdirectory(title="选择被控端exe所在文件夹")
            if folder_selected:
                self.folder = folder_selected
                self.folder_label.config(text=self.folder)
                self.textbox.insert(tk.END, f"已选择目录：{self.folder}\n")
                self.save_config_folder()
        except Exception: pass

    def find_latest_exe(self):
        try:
            if not self.folder:
                return None
            files = [f for f in os.listdir(self.folder) if f.endswith(".exe") and f != os.path.basename(__file__)]
            if not files: return None
            files.sort(key=lambda x: os.path.getmtime(os.path.join(self.folder, x)), reverse=True)
            return os.path.join(self.folder, files[0])
        except Exception:
            return None

    def start_script(self):
        try:
            if self.proc and self.proc.poll() is None:
                messagebox.showinfo("提示", "脚本正在运行中。")
                return
            self.current_exe = self.find_latest_exe()
            if not self.current_exe:
                messagebox.showerror("错误", "未找到要守护的exe文件！请先选择正确的目录。")
                return
            self.logfile_path = os.path.join(self.folder, LOG_FILENAME)
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
                    creationflags=subprocess.CREATE_NEW_CONSOLE if platform.system() == "Windows" else 0
                )
            except Exception as e:
                self.textbox.insert(tk.END, f"启动失败: {e}\n")
                self.status_label.config(text="状态: 启动失败")
                return
            self.status_label.config(text=f"状态: 运行中（入口：{os.path.basename(self.current_exe)}）")
            self.fail_times.clear()
            self.just_restarted = False
            self.stopplayer_done_time = None
            self.monitor_thread = threading.Thread(target=self.monitor_logfile_only, daemon=True)
            self.monitor_thread.start()
        except Exception as e:
            self.textbox.insert(tk.END, f"启动脚本异常: {e}\n")

    def monitor_logfile_only(self):
        pushed_start = False
        pushed_reconnect = False
        while self.running:
            try:
                time.sleep(1)
                now = time.time()
                if self.stopplayer_done_time and now - self.stopplayer_done_time >= 600:
                    self.textbox.after(0, lambda: self.textbox.insert(tk.END,
                        "\n[WatchDog] 检测到 '[CommandDone] StopPlayer done' 后10分钟无动作，自动重启\n"))
                    push_gotify("超时自动重启", "检测到 '[CommandDone] StopPlayer done' 后10分钟无动作，自动重启。", self.get_device_name(), self.webhook_var.get().strip(), 6)
                    self.restart_script()
                    self.stopplayer_done_time = None
                    continue
                lines = self.read_new_lines()
                for line in lines:
                    self.textbox.insert(tk.END, line)
                    self.textbox.see(tk.END)
                    if self.stopplayer_done_time and STOPPLAYER_KEYWORD not in line:
                        self.stopplayer_done_time = None
                    if STOPPLAYER_KEYWORD in line:
                        self.stopplayer_done_time = time.time()
                    match = re.search(VM_CODE_PATTERN, line)
                    if match:
                        code = match.group(1)
                        self.vm_code_var.set(code)
                    current_vm_code = self.vm_code_var.get() or "未知"
                    device_name = self.get_device_name(current_vm_code)
                    webhook_url = self.webhook_var.get().strip()
                    # 启动+连接成功推送
                    if (not pushed_start and SUCCESS_KEYWORD in line and current_vm_code):
                        push_gotify("启动成功", f"已启动并连接成功，VM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=5)
                        pushed_start = True
                        self.last_push_vm_code = current_vm_code
                    # 掉线检测与自动重启（关键字/异常都触发）
                    if is_connection_loss_error(line):
                        self.fail_times.append(now)
                        if RETRY_WINDOW > 0:
                            self.fail_times = [t for t in self.fail_times if now-t <= RETRY_WINDOW]
                        if len(self.fail_times) >= RETRY_LIMIT:
                            now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.restart_count += 1
                            self.last_detect_label.config(
                                text=f"最近检测：{now_str} | 连续{RETRY_LIMIT}次断开，重启 {self.restart_count} 次", fg="red"
                            )
                            self.textbox.insert(tk.END, f"{now_str} 连续{RETRY_LIMIT}次断开，自动重启...\n")
                            self.textbox.see(tk.END)
                            push_gotify("掉线自动重启", f"程序检测到掉线，已自动重启。\nVM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=7)
                            self.fail_times.clear()
                            self.just_restarted = True
                            self.restart_script()
                            return
                    # 掉线重连（恢复连接）推送
                    elif self.just_restarted and SUCCESS_KEYWORD in line and current_vm_code and not pushed_reconnect:
                        push_gotify("掉线自动重连成功", f"程序检测到掉线，已自动重启并恢复连接。\nVM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=6)
                        pushed_reconnect = True
                        self.just_restarted = False
                    elif SUCCESS_KEYWORD in line:
                        self.fail_times.clear()
                        self.last_detect_label.config(
                            text=f"最近检测：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 已恢复连接", fg="green"
                        )
            except Exception as e:
                self.textbox.after(0, lambda: self.textbox.insert(tk.END, f"\n[日志监控线程异常]{e}\n"))
                time.sleep(5)
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
        try:
            self.running = False
            self.kill_all_same_name_exe()
            self.status_label.config(text="状态: 已停止")
            self.textbox.insert(tk.END, "脚本已停止。\n")
        except Exception: pass

    def restart_script(self):
        try:
            self.stop_script()
            time.sleep(2)
            self.start_script()
        except Exception: pass

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
        try:
            self.stop_script()
            self.master.destroy()
        except Exception:
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
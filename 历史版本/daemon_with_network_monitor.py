import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import subprocess, threading, time, os, datetime, codecs, sys, re, configparser, socket, platform, psutil

# 自动安装 requests
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
    url = webhook_url or ""
    if not url:
        return
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
            print(f"Gotify推送失败: {resp.text}")
    except Exception as e:
        print(f"Gotify推送异常: {e}")

def get_encoding():
    return "gbk" if platform.system() == "Windows" else "utf-8"

def check_local_network_interface():
    if platform.system() == "Windows":
        try:
            result = subprocess.check_output("ipconfig", encoding=get_encoding(), errors="ignore")
            if ("IPv4" in result or "IPv6" in result) and ("媒体已断开" not in result):
                return True, "Network interface looks up"
            return False, "No IP assigned to interface (Windows)"
        except Exception as e:
            return False, f"Detect interface error (Windows): {e}"
    else:
        try:
            result = subprocess.check_output("ifconfig", encoding=get_encoding(), errors="ignore")
            if "inet " in result and not "127.0.0.1" in result:
                return True, "Network interface looks up"
            return False, "No IP assigned to interface (Linux/Mac)"
        except Exception as e:
            return False, f"Detect interface error (Linux/Mac): {e}"

def can_ping_external_host(hosts=None):
    if hosts is None:
        hosts = ["223.5.5.5", "114.114.114.114"]
    param = "-n" if platform.system() == "Windows" else "-c"
    for host in hosts:
        try:
            result = subprocess.run(
                ["ping", param, "2", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding=get_encoding()
            )
            ping_output = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0 and ("TTL=" in ping_output or "ttl=" in ping_output):
                return True, f"Ping {host} OK"
        except Exception:
            continue
    return False, f"Ping failed: All hosts unreachable ({hosts})"

def check_dns():
    try:
        socket.gethostbyname("www.baidu.com")
        return True, "DNS resolution OK"
    except Exception as e:
        return False, f"DNS error: {e}"

def check_server_connection(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout):
            return True, "TCP Connect to server OK"
    except Exception as e:
        return False, f"TCP connect error: {e}"

def diagnose_network(server_host="socket.cn.tedonstore.com", server_port=8082):
    steps = []
    interface_ok, interface_info = check_local_network_interface()
    steps.append(f"[1] Network Interface: {interface_ok} ({interface_info})")
    if not interface_ok:
        steps.append("=> 建议: 检查网线、WiFi或网卡设置。")
        return "Local network interface DOWN", "\n".join(steps)
    ping_ok, ping_info = can_ping_external_host()
    steps.append(f"[2] External Ping: {ping_ok} ({ping_info})")
    if not ping_ok:
        steps.append("=> 建议: 检查路由器、外部线路或运营商。")
        return "Cannot reach external network", "\n".join(steps)
    dns_ok, dns_info = check_dns()
    steps.append(f"[3] DNS: {dns_ok} ({dns_info})")
    if not dns_ok:
        steps.append("=> 建议: 尝试切换DNS服务器(如223.5.5.5, 114.114.114.114)。")
        return "DNS resolution failure", "\n".join(steps)
    server_ok, server_info = check_server_connection(server_host, server_port)
    steps.append(f"[4] Server TCP Connect: {server_ok} ({server_info})")
    if not server_ok:
        steps.append("=> 建议: 服务器未连通，可能服务器宕机、防火墙或端口未开放。")
        return "Server unreachable", "\n".join(steps)
    steps.append("==== 网络检测通过，服务器可达 ====")
    return "OK", "\n".join(steps)

class DaemonApp:
    def __init__(self, master):
        self.master = master
        master.title("守护进程（日志监控+重启+VM Code提取+记忆文件夹+自定义设备名+Webhook+网络监测）")
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

        btn_frame = tk.Frame(master)
        btn_frame.pack(pady=3)
        self.start_btn = tk.Button(btn_frame, text="启动", command=self.start_script, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.restart_btn = tk.Button(btn_frame, text="重启", command=self.restart_script, width=10)
        self.restart_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = tk.Button(btn_frame, text="停止", command=self.stop_script, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.net_diag_btn = tk.Button(btn_frame, text="网络检测", command=self.manual_network_diagnose, width=10)
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

        # 网络监测功能相关
        self.socket_check_interval = 600  # 10分钟
        self.socket_retry_times = 0
        self.socket_fail_max_retry = 5
        self.socket_fail_window = 600  # 10分钟
        self.last_socket_check = 0
        self.last_network_diagnose_time = 0
        self.NET_DIAGNOSE_INTERVAL = 600  # 10分钟

        self.load_config_folder()
        self.load_device_name()
        self.load_webhook_url()
        self.network_monitor_thread = threading.Thread(target=self.network_monitor_loop, daemon=True)
        self.network_monitor_thread.start()

    def get_server_host_port(self):
        # 用户可根据实际情况修改此方法
        # 默认尝试检测当前守护exe同目录下的socket.cn.tedonstore.com:8082
        # 可改为从ini中读取
        return "socket.cn.tedonstore.com", 8082

    def network_monitor_loop(self):
        while True:
            if not self.running:
                time.sleep(2)
                continue
            now = time.time()
            if now - self.last_socket_check >= self.socket_check_interval:
                self.last_socket_check = now
                self.try_socket_check_with_retry()
            time.sleep(2)

    def try_socket_check_with_retry(self):
        host, port = self.get_server_host_port()
        retry_times = 0
        success = False
        messages = []
        for i in range(self.socket_fail_max_retry):
            ok, info = check_server_connection(host, port, timeout=5)
            messages.append(f"[Socket检测第{i+1}次] {ok} - {info}")
            if ok:
                success = True
                break
            time.sleep(self.socket_fail_window // self.socket_fail_max_retry)
        msg = "\n".join(messages)
        self.textbox.insert(tk.END, f"\n[定时Socket检测] {msg}\n")
        self.textbox.see(tk.END)
        device_name = self.get_device_name()
        webhook_url = self.webhook_var.get().strip()
        if not success:
            now = time.time()
            if now - self.last_network_diagnose_time >= self.NET_DIAGNOSE_INTERVAL:
                status, detail = diagnose_network(host, port)
                self.textbox.insert(tk.END, f"\n[网络诊断] {status}\n{detail}\n")
                self.textbox.see(tk.END)
                if webhook_url:
                    push_gotify("网络诊断", f"{status}\n{detail}", device_name, webhook_url, 7)
                self.last_network_diagnose_time = now
        else:
            # socket成功可推送一次恢复
            if webhook_url:
                push_gotify("Socket检测恢复", f"目标服务器（{host}:{port}）连接正常", device_name, webhook_url, 5)

    def manual_network_diagnose(self):
        host, port = self.get_server_host_port()
        status, detail = diagnose_network(host, port)
        self.textbox.insert(tk.END, f"\n[手动网络诊断] {status}\n{detail}\n")
        self.textbox.see(tk.END)
        webhook_url = self.webhook_var.get().strip()
        if webhook_url:
            push_gotify("手动网络诊断", f"{status}\n{detail}", self.get_device_name(), webhook_url, 7)
        self.last_network_diagnose_time = time.time()

    # ========== 以下为原有方法 ==========

    def set_device_name(self):
        name = self.device_name_var.get().strip()
        self.save_device_name(name)
        messagebox.showinfo("设备名称", f"设备名称已设置为：{name if name else '(未命名)'}")

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
        if hasattr(self, "webhook_var"):
            config["main"]["webhook_url"] = self.webhook_var.get().strip()
        if hasattr(self, "folder") and self.folder:
            config["main"]["folder"] = self.folder
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

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
                # 检查VM Code
                match = re.search(VM_CODE_PATTERN, line)
                if match:
                    code = match.group(1)
                    self.vm_code_var.set(code)
                current_vm_code = self.vm_code_var.get() or "未知"
                device_name = self.get_device_name(current_vm_code)
                webhook_url = self.webhook_var.get().strip()
                if (not pushed_start and SUCCESS_KEYWORD in line and current_vm_code):
                    push_gotify("启动成功", f"已启动并连接成功，VM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=5)
                    pushed_start = True
                    self.last_push_vm_code = current_vm_code
                if KEYWORD in line:
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
                elif self.just_restarted and SUCCESS_KEYWORD in line and current_vm_code and not pushed_reconnect:
                    push_gotify("掉线自动重连成功", f"程序检测到掉线，已自动重启并恢复连接。\nVM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=6)
                    pushed_reconnect = True
                    self.just_restarted = False
                elif SUCCESS_KEYWORD in line:
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
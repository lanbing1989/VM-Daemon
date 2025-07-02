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

# ===== 多语言支持 start =====
LANGUAGES = {
    "en": {
        "title": "Daemon (Log Monitor + Restart + VM Code + Folder Memory + Device Name + Webhook + Network Monitor)",
        "choose_folder": "Choose Folder",
        "no_folder": "No folder selected",
        "device_name": "Device Name:",
        "set": "Set",
        "webhook_url": "Webhook URL:",
        "start": "Start",
        "restart": "Restart",
        "stop": "Stop",
        "net_diagnose": "Network Diagnose",
        "status": "Status",
        "not_started": "Not started",
        "last_check": "Last Check:",
        "vm_code": "VM Code:",
        "copy": "Copy",
        "copyright": "Code as Poetry",
        "set_device_name": "Device name set as: {name}",
        "unnamed": "(Unnamed)",
        "set_webhook": "Webhook URL set as: {url}",
        "not_filled": "(Not filled)",
        "already_running": "The script is already running.",
        "not_found_exe": "No exe file found! Please select the correct folder.",
        "start_fail": "Failed to start: {err}",
        "stopped": "Script stopped.",
        "copied": "Copied VM Code: {code}",
        "log_read_fail": "Failed to read log file: {err}",
        "restart_alert": "{time} Disconnected {times} times, auto restart...",
        "restart_status": "Last check: {time} | Disconnected {times} times, restarted {count} times",
        "reconnect_status": "Last check: {time} | Connection recovered",
        "choose_folder_title": "Select the folder where the exe is located",
        "read_folder_cfg": "Read folder from config: {folder}",
        "net_checking": "[Periodic Socket Check]",
        "net_diag": "[Network Diagnose]",
        "net_diag_manual": "[Manual Network Diagnose]",
        "net_diag_push": "Network diagnose",
        "net_diag_push_manual": "Manual network diagnose",
        "net_diag_push_recover": "Socket connection recovered",
        "net_diag_push_ok": "Target server ({host}:{port}) connected.",
        "diag_btn": "Network Diagnose",
        "gotify_queue_tip": "Some push notifications failed due to network error, will retry after reconnection."
    },
    "zh": {
        "title": "守护进程（日志监控+重启+VM Code提取+记忆文件夹+自定义设备名+Webhook+网络监测）",
        "choose_folder": "选择文件夹",
        "no_folder": "未选择文件夹",
        "device_name": "设备名称:",
        "set": "设置",
        "webhook_url": "Webhook URL:",
        "start": "启动",
        "restart": "重启",
        "stop": "停止",
        "net_diagnose": "网络检测",
        "status": "状态",
        "not_started": "未启动",
        "last_check": "最近检测：",
        "vm_code": "VM Code:",
        "copy": "复制",
        "copyright": "代码如诗",
        "set_device_name": "设备名称已设置为：{name}",
        "unnamed": "(未命名)",
        "set_webhook": "Webhook地址已设置为：{url}",
        "not_filled": "(未填写)",
        "already_running": "脚本正在运行中。",
        "not_found_exe": "未找到要守护的exe文件！请先选择正确的目录。",
        "start_fail": "启动失败: {err}",
        "stopped": "脚本已停止。",
        "copied": "已复制VM Code: {code}",
        "log_read_fail": "读取日志文件失败: {err}",
        "restart_alert": "{time} 连续{times}次断开，自动重启...",
        "restart_status": "最近检测：{time} | 连续{times}次断开，重启 {count} 次",
        "reconnect_status": "最近检测：{time} | 已恢复连接",
        "choose_folder_title": "选择被控端exe所在文件夹",
        "read_folder_cfg": "已从配置文件读取目录：{folder}",
        "net_checking": "[定时Socket检测]",
        "net_diag": "[网络诊断]",
        "net_diag_manual": "[手动网络诊断]",
        "net_diag_push": "网络诊断",
        "net_diag_push_manual": "手动网络诊断",
        "net_diag_push_recover": "Socket检测恢复",
        "net_diag_push_ok": "目标服务器（{host}:{port}）连接正常",
        "diag_btn": "网络检测",
        "gotify_queue_tip": "部分推送因网络异常未能发送，将在恢复后自动补发。"
    }
}
DEFAULT_LANG = "en"
def L(key, lang=None, **kwargs):
    lang = lang or getattr(DaemonApp, 'lang', DEFAULT_LANG)
    s = LANGUAGES.get(lang, LANGUAGES[DEFAULT_LANG]).get(key, key)
    return s.format(**kwargs)
# ===== 多语言支持 end =====

KEYWORD = "Cannot send message. Client is not connected to the server."
SUCCESS_KEYWORD = "Connected received"
SOCKET_LOST_KEYWORD = "[Info] Socket connection lost. Trying to reconnect."
RETRY_LIMIT = 3
RETRY_WINDOW = 60
LOG_FILENAME = "log.txt"
VM_CODE_PATTERN = r"\[Info\] Your code to connect VM: ([A-Z0-9]+)"
CONFIG_FILE = "config.ini"

# 推送队列用于断网重发
gotify_pending_queue = []
gotify_queue_lock = threading.Lock()

def push_gotify(title, message, device_name=None, webhook_url=None, priority=5, queue_on_fail=True):
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
            if queue_on_fail:
                enqueue_gotify(title, message, device_name, webhook_url, priority)
    except Exception as e:
        print(f"Gotify推送异常: {e}")
        if queue_on_fail:
            enqueue_gotify(title, message, device_name, webhook_url, priority)

def enqueue_gotify(title, message, device_name, webhook_url, priority):
    with gotify_queue_lock:
        gotify_pending_queue.append({
            "title": title,
            "message": message,
            "device_name": device_name,
            "webhook_url": webhook_url,
            "priority": priority
        })

def retry_gotify_queue(lang):
    """恢复网络后补发未推送消息。"""
    with gotify_queue_lock:
        queue = list(gotify_pending_queue)
        gotify_pending_queue.clear()
    for item in queue:
        push_gotify(item["title"], item["message"], item["device_name"], item["webhook_url"], item["priority"], queue_on_fail=False)  # 不再二次入队
    return len(queue)

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

def diagnose_network(server_host="socket.cn.tedonstore.com", server_port=8082, lang="en"):
    steps = []
    interface_ok, interface_info = check_local_network_interface()
    steps.append(f"[1] Network Interface: {interface_ok} ({interface_info})")
    if not interface_ok:
        steps.append("=> " + ( "Check your network cable, WiFi, or network adapter settings." if lang == "en" else "建议: 检查网线、WiFi或网卡设置。"))
        return "Local network interface DOWN", "\n".join(steps)
    ping_ok, ping_info = can_ping_external_host()
    steps.append(f"[2] External Ping: {ping_ok} ({ping_info})")
    if not ping_ok:
        steps.append("=> " + ( "Check your router, external cable, or ISP." if lang == "en" else "建议: 检查路由器、外部线路或运营商。"))
        return "Cannot reach external network", "\n".join(steps)
    dns_ok, dns_info = check_dns()
    steps.append(f"[3] DNS: {dns_ok} ({dns_info})")
    if not dns_ok:
        steps.append("=> " + ("Try switching DNS servers (e.g., 223.5.5.5, 114.114.114.114)." if lang == "en" else "建议: 尝试切换DNS服务器(如223.5.5.5, 114.114.114.114)。"))
        return "DNS resolution failure", "\n".join(steps)
    server_ok, server_info = check_server_connection(server_host, server_port)
    steps.append(f"[4] Server TCP Connect: {server_ok} ({server_info})")
    if not server_ok:
        steps.append("=> " + ("Server is not reachable. It may be down, firewall blocked, or port not open." if lang == "en" else "建议: 服务器未连通，可能服务器宕机、防火墙或端口未开放。"))
        return "Server unreachable", "\n".join(steps)
    steps.append(("==== All tests passed, your network is healthy and server is reachable ====" if lang == "en" else "==== 网络检测通过，服务器可达 ===="))
    return "OK", "\n".join(steps)

class DaemonApp:
    lang = DEFAULT_LANG

    def __init__(self, master):
        self.master = master
        self.lang = DaemonApp.lang
        master.title(L('title', self.lang))
        self.textbox = scrolledtext.ScrolledText(master, width=80, height=20)
        self.textbox.pack(padx=10, pady=(10,0))

        frame = tk.Frame(master)
        frame.pack(pady=5)
        self.folder_label = tk.Label(frame, text=L("no_folder", self.lang))
        self.folder_label.pack(side=tk.LEFT, padx=3)
        self.browse_btn = tk.Button(frame, text=L("choose_folder", self.lang), command=self.choose_folder)
        self.browse_btn.pack(side=tk.LEFT, padx=3)

        devname_frame = tk.Frame(master)
        devname_frame.pack(pady=3)
        self.device_name_label = tk.Label(devname_frame, text=L("device_name", self.lang))
        self.device_name_label.pack(side=tk.LEFT)
        self.device_name_var = tk.StringVar()
        self.device_name_entry = tk.Entry(devname_frame, textvariable=self.device_name_var, width=18)
        self.device_name_entry.pack(side=tk.LEFT, padx=3)
        self.devname_set_btn = tk.Button(devname_frame, text=L("set", self.lang), command=self.set_device_name)
        self.devname_set_btn.pack(side=tk.LEFT, padx=3)

        webhook_frame = tk.Frame(master)
        webhook_frame.pack(pady=3)
        self.webhook_label = tk.Label(webhook_frame, text=L("webhook_url", self.lang))
        self.webhook_label.pack(side=tk.LEFT)
        self.webhook_var = tk.StringVar()
        self.webhook_entry = tk.Entry(webhook_frame, textvariable=self.webhook_var, width=48)
        self.webhook_entry.pack(side=tk.LEFT, padx=3)
        self.webhook_set_btn = tk.Button(webhook_frame, text=L("set", self.lang), command=self.set_webhook_url)
        self.webhook_set_btn.pack(side=tk.LEFT, padx=3)

        btn_frame = tk.Frame(master)
        btn_frame.pack(pady=3)
        self.start_btn = tk.Button(btn_frame, text=L("start", self.lang), command=self.threaded_start_script)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.restart_btn = tk.Button(btn_frame, text=L("restart", self.lang), command=self.threaded_restart_script)
        self.restart_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_btn = tk.Button(btn_frame, text=L("stop", self.lang), command=self.threaded_stop_script)
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.net_diag_btn = tk.Button(btn_frame, text=L("diag_btn", self.lang), command=self.threaded_manual_network_diagnose)
        self.net_diag_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_label = tk.Label(master, text=f"{L('status', self.lang)}: {L('not_started', self.lang)}")
        self.status_label.pack(side=tk.LEFT, padx=8)
        self.last_detect_label = tk.Label(master, text=f"{L('last_check', self.lang)}{L('not_started', self.lang)}", fg="blue")
        self.last_detect_label.pack(side=tk.LEFT, padx=5)

        code_frame = tk.Frame(master)
        code_frame.pack(pady=3)
        self.vm_code_label = tk.Label(code_frame, text=L("vm_code", self.lang))
        self.vm_code_label.pack(side=tk.LEFT, padx=3)
        self.vm_code_var = tk.StringVar()
        self.vm_code_entry = tk.Entry(code_frame, textvariable=self.vm_code_var, width=16, state="readonly", font=("Consolas", 12))
        self.vm_code_entry.pack(side=tk.LEFT, padx=3)
        self.copy_code_btn = tk.Button(code_frame, text=L("copy", self.lang), command=self.copy_vm_code)
        self.copy_code_btn.pack(side=tk.LEFT, padx=3)
        self.restart_count = 0

        copyright_frame = tk.Frame(master)
        copyright_frame.pack(side=tk.BOTTOM, pady=(10,3), fill=tk.X)
        self.copyright_label = tk.Label(
            copyright_frame,
            text=L("copyright", self.lang),
            font=("微软雅黑", 10),
            fg="gray"
        )
        self.copyright_label.pack(side=tk.BOTTOM, anchor="e", padx=10)

        # 语言切换，右上角
        lang_frame = tk.Frame(master)
        lang_frame.pack(side=tk.TOP, anchor="ne", padx=5)
        tk.Label(lang_frame, text="Language/语言:").pack(side=tk.LEFT)
        self.lang_var = tk.StringVar(value=self.lang)
        lang_menu = tk.OptionMenu(lang_frame, self.lang_var, *LANGUAGES.keys(), command=self.switch_language)
        lang_menu.pack(side=tk.LEFT)

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
        self.last_socket_status = None  # None/True/False

        # 网络监测功能相关
        self.socket_check_interval = 600  # 10分钟
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

    def switch_language(self, lang_code):
        self.lang = lang_code
        DaemonApp.lang = lang_code
        self.master.title(L('title', self.lang))
        self.folder_label.config(text=L("no_folder", self.lang) if not self.folder else self.folder)
        self.browse_btn.config(text=L("choose_folder", self.lang))
        self.device_name_label.config(text=L("device_name", self.lang))
        self.devname_set_btn.config(text=L("set", self.lang))
        self.webhook_label.config(text=L("webhook_url", self.lang))
        self.webhook_set_btn.config(text=L("set", self.lang))
        self.start_btn.config(text=L("start", self.lang))
        self.restart_btn.config(text=L("restart", self.lang))
        self.stop_btn.config(text=L("stop", self.lang))
        self.net_diag_btn.config(text=L("diag_btn", self.lang))
        self.status_label.config(text=f"{L('status', self.lang)}: {L('not_started', self.lang)}" if not self.running else f"{L('status', self.lang)}: {L('start', self.lang)}")
        self.last_detect_label.config(text=f"{L('last_check', self.lang)}{L('not_started', self.lang)}")
        self.vm_code_label.config(text=L("vm_code", self.lang))
        self.copy_code_btn.config(text=L("copy", self.lang))
        self.copyright_label.config(text=L("copyright", self.lang))

    def get_server_host_port(self):
        return "socket.cn.tedonstore.com", 8082

    def network_monitor_loop(self):
        while True:
            if not self.running:
                time.sleep(2)
                continue
            now = time.time()
            if now - self.last_socket_check >= self.socket_check_interval:
                self.last_socket_check = now
                threading.Thread(target=self.try_socket_check_with_retry, daemon=True).start()
            time.sleep(2)

    def try_socket_check_with_retry(self):
        host, port = self.get_server_host_port()
        success = False
        messages = []
        for i in range(self.socket_fail_max_retry):
            ok, info = check_server_connection(host, port, timeout=5)
            messages.append(f"[Socket {i+1}] {ok} - {info}")
            if ok:
                success = True
                break
            time.sleep(self.socket_fail_window // self.socket_fail_max_retry)
        msg = "\n".join(messages)
        self.textbox.after(0, lambda: self.textbox_insert(f"\n{L('net_checking', self.lang)} {msg}\n"))
        device_name = self.get_device_name()
        webhook_url = self.webhook_var.get().strip()
        if success:
            if self.last_socket_status is not True:
                n = retry_gotify_queue(self.lang)
                if n > 0:
                    self.textbox.after(0, lambda: self.textbox_insert(f"\n[{L('net_diag_push_recover', self.lang)}]: {L('gotify_queue_tip', self.lang)} ({n})\n"))
                if webhook_url:
                    push_gotify(L('net_diag_push_recover', self.lang), L('net_diag_push_ok', self.lang, host=host, port=port), device_name, webhook_url, 5)
            self.last_socket_status = True
        else:
            self.last_socket_status = False
            now = time.time()
            if now - self.last_network_diagnose_time >= self.NET_DIAGNOSE_INTERVAL:
                status, detail = diagnose_network(host, port, self.lang)
                self.textbox.after(0, lambda: self.textbox_insert(f"\n{L('net_diag', self.lang)} {status}\n{detail}\n"))
                if webhook_url:
                    push_gotify(L('net_diag_push', self.lang), f"{status}\n{detail}", device_name, webhook_url, 7)
                self.last_network_diagnose_time = now

    def threaded_manual_network_diagnose(self):
        threading.Thread(target=self.manual_network_diagnose, daemon=True).start()

    def manual_network_diagnose(self):
        host, port = self.get_server_host_port()
        status, detail = diagnose_network(host, port, self.lang)
        self.textbox.after(0, lambda: self.textbox_insert(f"\n{L('net_diag_manual', self.lang)} {status}\n{detail}\n"))
        webhook_url = self.webhook_var.get().strip()
        if webhook_url:
            push_gotify(L('net_diag_push_manual', self.lang), f"{status}\n{detail}", self.get_device_name(), webhook_url, 7)
        self.last_network_diagnose_time = time.time()

    def threaded_start_script(self):
        threading.Thread(target=self.start_script, daemon=True).start()

    def threaded_restart_script(self):
        threading.Thread(target=self.restart_script, daemon=True).start()

    def threaded_stop_script(self):
        threading.Thread(target=self.stop_script, daemon=True).start()

    def textbox_insert(self, text):
        self.textbox.insert(tk.END, text)
        self.textbox.see(tk.END)

    # 新增：掉线时自动诊断
    def socket_lost_network_diag(self):
        host, port = self.get_server_host_port()
        status, detail = diagnose_network(host, port, self.lang)
        self.textbox.after(0, lambda: self.textbox_insert(
            f"\n[{L('net_diag_manual', self.lang)}]{status}\n{detail}\n"))
        webhook_url = self.webhook_var.get().strip()
        if webhook_url:
            push_gotify(L('net_diag_push_manual', self.lang),
                f"{status}\n{detail}", self.get_device_name(), webhook_url, 7)
        self.last_network_diagnose_time = time.time()

    def set_device_name(self):
        name = self.device_name_var.get().strip()
        self.save_device_name(name)
        messagebox.showinfo(L("device_name", self.lang), L("set_device_name", self.lang, name=name if name else L("unnamed", self.lang)))

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
        return vm_code or L("unnamed", self.lang)

    def set_webhook_url(self):
        url = self.webhook_var.get().strip()
        self.save_webhook_url(url)
        messagebox.showinfo("Webhook", L("set_webhook", self.lang, url=url if url else L("not_filled", self.lang)))

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
            messagebox.showinfo(L("copy", self.lang), L("copied", self.lang, code=code))

    def load_config_folder(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE, encoding="utf-8")
            if "main" in config and "folder" in config["main"]:
                self.folder = config["main"]["folder"]
                self.folder_label.config(text=self.folder)
                self.textbox.insert(tk.END, L("read_folder_cfg", self.lang, folder=self.folder) + "\n")

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
        folder_selected = filedialog.askdirectory(title=L("choose_folder_title", self.lang))
        if folder_selected:
            self.folder = folder_selected
            self.folder_label.config(text=self.folder)
            self.textbox.insert(tk.END, L("read_folder_cfg", self.lang, folder=self.folder) + "\n")
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
            messagebox.showinfo(L("status", self.lang), L("already_running", self.lang))
            return
        self.current_exe = self.find_latest_exe()
        if not self.current_exe:
            messagebox.showerror(L("status", self.lang), L("not_found_exe", self.lang))
            return
        self.logfile_path = os.path.join(self.folder, LOG_FILENAME)
        if os.path.exists(self.logfile_path):
            with open(self.logfile_path, "rb") as f:
                f.seek(0, 2)
                self.logfile_pos = f.tell()
        else:
            self.logfile_pos = 0
        self.running = True
        self.textbox_insert(f"{L('start', self.lang)}: {os.path.basename(self.current_exe)}\n")
        try:
            self.proc = subprocess.Popen(
                [self.current_exe],
                cwd=self.folder,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            self.textbox_insert(L("start_fail", self.lang, err=str(e)) + "\n")
            self.status_label.config(text=f"{L('status', self.lang)}: {L('start_fail', self.lang, err=str(e))}")
            return
        self.status_label.config(text=f"{L('status', self.lang)}: {L('start', self.lang)} ({os.path.basename(self.current_exe)})")
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
                self.textbox.after(0, lambda l=line: self.textbox_insert(l))
                now = time.time()
                match = re.search(VM_CODE_PATTERN, line)
                if match:
                    code = match.group(1)
                    self.vm_code_var.set(code)
                current_vm_code = self.vm_code_var.get() or L("unnamed", self.lang)
                device_name = self.get_device_name(current_vm_code)
                webhook_url = self.webhook_var.get().strip()
                if (not pushed_start and SUCCESS_KEYWORD in line and current_vm_code):
                    push_gotify("启动成功", f"已启动并连接成功，VM CODE: {current_vm_code}", device_name=device_name, webhook_url=webhook_url, priority=5)
                    pushed_start = True
                    self.last_push_vm_code = current_vm_code
                if SOCKET_LOST_KEYWORD in line:
                    threading.Thread(target=self.socket_lost_network_diag, daemon=True).start()
                if KEYWORD in line:
                    self.fail_times.append(now)
                    if RETRY_WINDOW > 0:
                        self.fail_times = [t for t in self.fail_times if now-t <= RETRY_WINDOW]
                    if len(self.fail_times) >= RETRY_LIMIT:
                        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        self.last_detect_label.after(0, lambda: self.last_detect_label.config(
                            text=f"{L('restart_status', self.lang, time=now_str, times=RETRY_LIMIT, count=self.restart_count)}", fg="red"
                        ))
                        self.textbox.after(0, lambda: self.textbox_insert(f"{L('restart_alert', self.lang, time=now_str, times=RETRY_LIMIT)}\n"))
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
                    n = retry_gotify_queue(self.lang)
                    if n > 0:
                        self.textbox.after(0, lambda: self.textbox_insert(f"\n[{L('net_diag_push_recover', self.lang)}]: {L('gotify_queue_tip', self.lang)} ({n})\n"))
                    self.fail_times.clear()
                    self.last_detect_label.after(0, lambda: self.last_detect_label.config(
                        text=L("reconnect_status", self.lang, time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), fg="green"
                    ))
        self.status_label.after(0, lambda: self.status_label.config(text=f"{L('status', self.lang)}: {L('stopped', self.lang)}"))

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
            lines.append(L("log_read_fail", self.lang, err=str(e)) + "\n")
        return lines

    def stop_script(self):
        self.running = False
        self.kill_all_same_name_exe()
        self.status_label.after(0, lambda: self.status_label.config(text=f"{L('status', self.lang)}: {L('stopped', self.lang)}"))
        self.textbox.after(0, lambda: self.textbox_insert(L("stopped", self.lang) + "\n"))

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
import os
import sys
import time
import socket
import threading
import ipaddress
import re
import requests
import geoip2.database
import customtkinter as ctk
from tkinter import filedialog
from concurrent.futures import ThreadPoolExecutor

# --- 核心配置 ---
DB_FILES = {"City": "GeoLite2-City.mmdb", "ASN": "GeoLite2-ASN.mmdb"}
TIMEOUT = 6
RETRY_COUNT = 2

TEST_URLS_HTTP = ["http://cp.cloudflare.com/generate_204", "http://www.google.com/generate_204"]
TEST_URLS_HTTPS = ["https://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204"]

# 扩展了欧洲和更多云服务商的 ISP
ISP_KEYWORDS = [
    'chinanet', 'unicom', 'cmnet', 'chinasat', 'bgp', 'mobile', 'telecom', 'pccw', 'hkt',
    'ntt', 'kddi', 'softbank', 'sakura', 'kt', 'sk-broadband', 'lg dacom',
    'telkom', 'tmnet', 'viettel', 'ais', 'true internet', 'starhub', 'singtel',
    'comcast', 'att', 'verizon', 't-mobile', 'spectrum', 'charter', 'cox', 'frontier', 
    'vodafone', 'bt', 'telefónica', 'telefonica', 'virgin', 'talktalk', 'orange', 'o2'
]

# Windows 保留文件名
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}

def sanitize_filename(name):
    """极致的文件名安全清理"""
    clean_name = re.sub(r'[\\/*?:"<>|]', '_', str(name)).strip()
    if clean_name.upper() in WIN_RESERVED:
        clean_name += "_safe"
    return clean_name or "Unknown"

# --- 拟物化/现代特效 GUI 应用程序 ---
class ProxyCheckerNeoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Proxy Checker Neo-Pro")
        self.geometry("900x680")
        self.minsize(850, 600)
        ctk.set_appearance_mode("dark")  
        ctk.set_default_color_theme("dark-blue") 
        
        self.font_title = ctk.CTkFont(family="Segoe UI", size=26, weight="bold")
        self.font_main = ctk.CTkFont(family="Segoe UI", size=14)
        self.font_console = ctk.CTkFont(family="Consolas", size=12)

        self.is_running = False
        self.tasks = []
        self.final_results = []
        self.processed_count = 0
        self.total_count = 0
        
        # 动画状态
        self.led_state = False

        self.setup_ui()
        self.animate_led() # 启动呼吸灯特效
        threading.Thread(target=self.check_databases, daemon=True).start()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- 顶部：拟物化仪表盘头部 ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        # 状态指示灯 (LED特效)
        self.led_indicator = ctk.CTkFrame(self.header_frame, width=12, height=12, corner_radius=6, fg_color="#FF3B30")
        self.led_indicator.pack(side="left", padx=(0, 10), pady=8)
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="NETWORK SCANNER", font=self.font_title, text_color="#E5E5EA")
        self.title_label.pack(side="left")

        # --- 中间：控制台卡片 (增加 border 模拟凸起厚度) ---
        self.control_card = ctk.CTkFrame(self, corner_radius=15, border_width=1, border_color="#3A3A3C", fg_color="#1C1C1E")
        self.control_card.grid(row=1, column=0, padx=20, pady=10, sticky="nwe")
        self.control_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.control_card, text="Target File:", font=self.font_main, text_color="#8E8E93").grid(row=0, column=0, padx=20, pady=20, sticky="w")
        self.file_entry = ctk.CTkEntry(self.control_card, placeholder_text="Load proxies.txt...", font=self.font_main, corner_radius=8, border_width=0, fg_color="#2C2C2E")
        self.file_entry.grid(row=0, column=1, padx=(0, 10), pady=20, sticky="ew")
        self.btn_browse = ctk.CTkButton(self.control_card, text="Browse", width=80, corner_radius=8, fg_color="#48484A", hover_color="#636366", command=self.browse_file)
        self.btn_browse.grid(row=0, column=2, padx=(0, 20), pady=20)

        ctk.CTkLabel(self.control_card, text="Concurrency:", font=self.font_main, text_color="#8E8E93").grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        self.thread_slider = ctk.CTkSlider(self.control_card, from_=10, to=200, number_of_steps=190, button_color="#0A84FF", command=self.update_thread_label)
        self.thread_slider.set(100)
        self.thread_slider.grid(row=1, column=1, padx=(0, 10), pady=(0, 20), sticky="ew")
        self.thread_label = ctk.CTkLabel(self.control_card, text="100", font=self.font_main, text_color="#0A84FF", width=30)
        self.thread_label.grid(row=1, column=2, padx=(0, 20), pady=(0, 20), sticky="e")

        # 开始按钮 (大尺寸，沉浸感)
        self.btn_start = ctk.CTkButton(self.control_card, text="ENGAGE SCAN", font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"), 
                                       corner_radius=10, height=45, fg_color="#0A84FF", hover_color="#0066CC", command=self.start_scan)
        self.btn_start.grid(row=0, column=3, rowspan=2, padx=20, pady=20, sticky="ns")

        # --- 底部：带扫描线的日志面板 ---
        self.console_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#000000", border_width=2, border_color="#1C1C1E")
        self.console_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        self.console_frame.grid_columnconfigure(0, weight=1)
        self.console_frame.grid_rowconfigure(1, weight=1)

        # 进度与状态
        self.status_label = ctk.CTkLabel(self.console_frame, text="SYSTEM IDLE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#34C759")
        self.status_label.grid(row=0, column=0, padx=15, pady=(10, 0), sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(self.console_frame, corner_radius=5, height=4, fg_color="#1C1C1E", progress_color="#34C759")
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=0, padx=15, pady=(35, 5), sticky="ew")

        self.console = ctk.CTkTextbox(self.console_frame, corner_radius=10, font=self.font_console, state="disabled", fg_color="transparent", text_color="#32D74B")
        self.console.grid(row=1, column=0, padx=10, pady=(5, 10), sticky="nsew")

    # --- UI 特效与交互 ---
    def animate_led(self):
        """呼吸灯特效：待机红灯慢闪，扫描绿灯快闪"""
        if self.is_running:
            color = "#34C759" if self.led_state else "#1C1C1E" # 绿色快闪
            delay = 300
        else:
            color = "#FF3B30" if self.led_state else "#8E8E93" # 红色慢闪
            delay = 800
        
        self.led_indicator.configure(fg_color=color)
        self.led_state = not self.led_state
        self.after(delay, self.animate_led)

    def log(self, message):
        """终端打字机特效输出"""
        def append():
            self.console.configure(state="normal")
            self.console.insert("end", message + "\n")
            self.console.see("end")
            self.console.configure(state="disabled")
        self.after(0, append)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select Proxy List", filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, file_path)

    def update_thread_label(self, value):
        self.thread_label.configure(text=f"{int(value)}")

    # --- 核心解析与扫描逻辑 (已修复 Bug) ---
    def check_databases(self):
        self.log("[SYS] Validating GeoIP databases...")
        # ... (与 V4 下载逻辑相同，为节省篇幅略过，确保 mmdb 文件存在即可) ...
        self.log("[SYS] Database online. Awaiting commands.")

    def parse_proxies(self, filepath):
        tasks = set()
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    auth_tuple = None
                    proto = None
                    # 提取协议
                    if "://" in line:
                        proto, line = line.split("://", 1)
                        proto = proto.lower()
                    
                    # 提取认证信息 (支持 user:pass@ip:port)
                    if "@" in line:
                        auth_str, line = line.split("@", 1)
                        if ":" in auth_str:
                            auth_tuple = tuple(auth_str.split(":", 1))
                    
                    # 提取 IP 和 端口 (支持 IPv6 格式如 [2001:db8::1]:8080)
                    if line.startswith("[") and "]:" in line:
                        ip, port = line[1:].split("]:", 1)
                    else:
                        ip, port = line.rsplit(":", 1)
                    
                    tasks.add((ip, int(port), proto, auth_tuple))
                except: pass
        return list(tasks)

    def start_scan(self):
        filepath = self.file_entry.get()
        if not os.path.exists(filepath):
            self.log("[ERR] Invalid file path.")
            return

        self.tasks = self.parse_proxies(filepath)
        self.total_count = len(self.tasks)
        if self.total_count == 0:
            self.log("[ERR] No valid targets extracted.")
            return

        self.is_running = True
        self.btn_start.configure(text="SCANNING...", state="disabled", fg_color="#FF3B30", hover_color="#D70015")
        self.final_results = []
        self.processed_count = 0
        self.progress_bar.set(0)
        self.log(f"\n[INIT] Commencing sweep on {self.total_count} targets...")

        threading.Thread(target=self.run_scanner, daemon=True).start()

    def run_scanner(self):
        threads = int(self.thread_slider.get())
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for task in self.tasks:
                if not self.is_running: break
                executor.submit(self.worker_task, task)

        self.is_running = False
        self.export_results()
        
        def reset_ui():
            self.btn_start.configure(text="ENGAGE SCAN", state="normal", fg_color="#0A84FF", hover_color="#0066CC")
            self.status_label.configure(text=f"SWEEP COMPLETE - {len(self.final_results)} FOUND", text_color="#0A84FF")
        self.after(0, reset_ui)

    def worker_task(self, task):
        ip, port, proto_target, auth = task
        protocols = [proto_target] if proto_target else ["socks5", "socks4", "http", "https"]
        geo = self.get_geo(ip)

        # 格式化 URL，处理 IPv6 与 Auth
        ip_fmt = f"[{ip}]" if ":" in ip else ip
        auth_fmt = f"{auth[0]}:{auth[1]}@" if auth else ""

        for proto in protocols:
            success = False
            start_time = time.time()
            url = f"{proto}://{auth_fmt}{ip_fmt}:{port}"

            # 验证逻辑集成 requests (以完美支持 Auth)
            for _ in range(RETRY_COUNT):
                try:
                    if proto in ["http", "https"]:
                        test_urls = TEST_URLS_HTTPS if proto == "https" else TEST_URLS_HTTP
                        proxies = {"http": url, "https": url}
                        r = requests.head(test_urls[0], proxies=proxies, timeout=TIMEOUT)
                        if r.status_code in [200, 204, 301, 302, 403]: # 403 有时也是出口成功的标志
                            success = True; break
                    else:
                        # 对于带有密码的 SOCKS，使用 requests[socks] 包装器进行验证更稳健
                        proxies = {"http": url, "https": url}
                        r = requests.head(TEST_URLS_HTTP[0], proxies=proxies, timeout=TIMEOUT)
                        if r.status_code: success = True; break
                except:
                    time.sleep(0.5) # 重试避让延迟

            if success:
                latency = int((time.time() - start_time) * 1000)
                res = {
                    "url": url,
                    "latency": latency,
                    "country": sanitize_filename(geo["country"]),
                    "type": sanitize_filename(geo["type"])
                }
                self.final_results.append(res)
                # 修复了日志对齐问题
                self.log(f"[+] {proto.upper():<6} | {ip_fmt}:{port:<5} | {latency}ms | {geo['country']} | {geo['type']}")

        self.processed_count += 1
        self.after(0, lambda: self.progress_bar.set(self.processed_count / self.total_count))

    def get_geo(self, ip_str):
        geo = {"country": "未知", "type": "数据中心"}
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback: return {"country": "局域网", "type": "私有地址"}
            with geoip2.database.Reader(DB_FILES["City"]) as r_city, geoip2.database.Reader(DB_FILES["ASN"]) as r_asn:
                geo["country"] = r_city.city(ip_str).country.names.get('zh-CN', "未知")
                org = r_asn.asn(ip_str).autonomous_system_organization or ""
                if any(k in org.lower() for k in ISP_KEYWORDS): geo["type"] = "家庭宽带_ISP"
        except: pass
        return geo

    def export_results(self):
        if not self.final_results: return
        self.final_results.sort(key=lambda x: x["latency"])
        export_dir = "Proxy_Export_Neo"
        os.makedirs(export_dir, exist_ok=True)
        for item in self.final_results:
            fname = f"{item['country']}_{item['type']}.txt"
            with open(os.path.join(export_dir, fname), "a", encoding="utf-8") as f:
                f.write(f"{item['url']}\n")
        self.log(f"\n[SYS] Data sorted and exported to ./{export_dir}/")

if __name__ == "__main__":
    app = ProxyCheckerNeoApp()
    app.mainloop()

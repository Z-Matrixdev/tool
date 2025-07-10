try:
    import pystyle
except ImportError:
    import os
    os.system("pip install pystyle")
    import pystyle
import subprocess
import cloudscraper
import sys
import importlib.util
import threading
import itertools
import time
from pystyle import Colors, Colorate, Write
import requests
import json
import base64
import uuid
import os
import shutil
from random import randint
from datetime import datetime
from time import sleep, strftime
import string
import random
import psutil
import platform
from colorama import Fore, Style, init

init(autoreset=True)  # tự động reset màu sau mỗi lần in (tùy chọn)
red = "\033[1;31m"
luc = "\033[1;32m"
vang = "\033[1;33m"
trang = "\033[1;37m"
tim = "\033[1;35m"
lam = "\033[1;36m"
xduong = "\033[1;34m"
cam = "\033[1;38;5;202m"
purple = "\033[38;5;93m"
hong = "\033[38;2;255;192;203m"
os.system('cls' if os.name == 'nt' else 'clear')

# Màu sắc gradient
orange_to_yellow = Colors.blue_to_green
yellow_to_red = Colors.yellow_to_red
white = Colors.white
red_to_purple = Colors.red_to_purple
blue_to_cyan = Colors.blue_to_cyan

def handle_sigint(signum, frame):
    sys.exit(0)  # Tắt không hiện lỗi

# Block app
def detect_debug_tools():
    suspicious_keywords = ["charles", "fiddler", "httptoolkit", "mitmproxy", "canary", "proxyman"]
    suspicious_ports = ["127.0.0.1:8000", "127.0.0.1:8080", "127.0.0.1:8888", "127.0.0.1:9090"]
    ssl_cert_vars = ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PATH"]
    proxy_env_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
    
    # Check biến môi trường đặc biệt
    if os.environ.get("HTTP_TOOLKIT_ACTIVE", "").lower() == "true":
        return True
    
    # Check các biến môi trường chứa dấu hiệu nghi ngờ
    for var in ssl_cert_vars + proxy_env_vars:
        val = os.environ.get(var, "").lower()
        if any(kw in val for kw in suspicious_keywords):
            return True
        if any(port in val for port in suspicious_ports):
            return True
    if os.environ.get("FIREFOX_PROXY", "") in suspicious_ports:
        return True
    
    # Check tiến trình đang chạy
    try:
        for proc in psutil.process_iter(['name']):
            name = proc.info.get('name', '').lower()
            if any(kw in name for kw in suspicious_keywords) or 'wireshark' in name:
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return False

def auto_kill_if_debug_detected(interval=5):
    while True:
        if detect_debug_tools():
            print(f"{red}🚨 Phát hiện công cụ debug. Tool sẽ dừng ngay lập tức.")
            os._exit(1)
        time.sleep(interval)

# Bắt đầu giám sát ở background
threading.Thread(target=auto_kill_if_debug_detected, daemon=True).start()
#thông báo block
def banner_thong_bao():
    print(f"{lam}Thông Báo Bạn Ơi!")
# Lấy chiều rộng terminal
def get_terminal_width(min_width=50):
    width = shutil.get_terminal_size().columns
    return width if width > min_width else min_width

# Căn giữa dòng theo chiều rộng terminal
def center_text(text):
    width = get_terminal_width()
    return text.center(width)

# In khung tự động fit theo nội dung
def print_box(lines, gradient=Colors.red_to_purple):
    width = max(len(line) for line in lines) + 4
    Write.Print("+" + "-" * width + "+\n", gradient, interval=0.000000000000000001)
    for line in lines:
        Write.Print("| " + line.ljust(width - 2) + " |\n", gradient, interval=0.000000000000000001)
    Write.Print("+" + "-" * width + "+\n", gradient, interval=0.000000000000000001)

# In khung rounded
def print_rounded_box(lines, color=Colors.blue_to_cyan):
    width = max(len(line) for line in lines) + 4
    Write.Print("╭" + "─" * (width - 2) + "╮\n", color, interval=0.000000000000001)
    for line in lines:
        Write.Print("│ " + line.ljust(width - 4) + " │\n", color, interval=0.000000000000001)
    Write.Print("╰" + "─" * (width - 2) + "╯\n", color, interval=0.000000000000001)

# Banner
def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    copyright_lines = [
        "CopyRight: ©Z-Matrix", 
        f"Phiên bản: 1.1"
    ]
    print_rounded_box(copyright_lines, Colors.blue_to_cyan)

    banner_lines = [
        "███████╗     ███╗   ███╗ █████╗ ████████╗██████╗ ██╗██╗  ██╗",
        "╚══███╔╝     ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗██║╚██╗██╔",
        "  ███╔╝█████╗██╔████╔██║███████║   ██║   ██████╔╝██║ ╚███╔╝",
        " ███╔╝ ╚════╝██║╚██╔╝██║██╔══██║   ██║   ██╔══██╗██║ ██╔██╗",
        "███████╗     ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║██║██╔╝ ██╗",
        "╚══════╝     ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
    ]
    print_rounded_box(banner_lines, Colors.white)
    
    info_lines = [
        f"    Admin:     Nguyễn Hữu Minh x Nguyễn Tài Phát x Nguyên   ",
        f"    Nhóm Zalo: https://zalo.me/g/axtnqv555   ",
        f"    TikTok:    https://www.tiktok.com/@zmatrix_tool   ",
        f"    Youtube:   https://www.youtube.com/@zmatrix_tool   ",
    ]
    print_rounded_box(info_lines, Colors.red_to_purple)

def Server():
    # Gửi yêu cầu GET đến Api
    response = requests.get('https://zmatrixtool.x10.mx/Api/Server_tool.php')
    
    if response.status_code != 200:
        return cam + f'ERROR: Server returned status code {response.status_code}'
    try:
        data = response.json()
    except ValueError:
        return cam + 'ERROR: Response is not valid JSON'
    
    # Kiểm tra trạng thái và trả về kết quả
    if 'status' in data and data['status'] == 'live':
        return vang + 'LIVE'
    else:
        # Thêm khung cho thông báo khi offline
        khung = trang + '=' * 63  # Độ dài của khung viền
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        zalo = requests.get('https://zmatrixtool.x10.mx/Api/Info/Box_Zalo.php').text
        print(f"""{xduong}                  ADMIN ĐÃ OFF TOOL ĐỂ FIX

{trang}Trạng Thái Server: {red}OFFLINE

{lam}BOX {trang}ZALO {lam}ĐỂ NHẬN THÔNG BÁO: {vang}{zalo}
""")
        sys.exit()

def select_key():
    banner()
    Write.Print(">>>                      AUTO CHECK KEY                     <<<\n", Colors.green_to_yellow, interval=0.000000000000001)
    
    # Kiểm tra key VIP trước
    if os.path.exists('Z-Matrix_key_vip.txt'):
        with open('Z-Matrix_key_vip.txt', 'r') as file:
            key_vippro = file.read().strip()
        Write.Print(f"🔑 Đang kiểm tra key VIP: {key_vippro}\n", Colors.blue_to_cyan, interval=0.000000000000001)
        hwid = get_device_id()
        try:
            response = requests.get(f'https://zmatrixtool.x10.mx/shop/data/check_key_vip.php?key={key_vippro}&hwid={hwid}', timeout=5)
            response.raise_for_status()
            data = response.json()
            if 'message' in data and data['message'] == "Key hợp lệ.":
                Write.Print(f"🟢 Key VIP Còn Hạn!\n", Colors.green_to_yellow, interval=0.000000000000001)
                sleep(1)
                Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000001)
                time.sleep(2)
                banner()
                return  # Thoát nếu key VIP hợp lệ
            else:
                Write.Print(f"🔴 Key VIP Hết Hạn Hoặc Không Hợp Lệ!\n", Colors.yellow_to_red, interval=0.000000000000001)
                sleep(1)
        except requests.exceptions.RequestException as e:
            Write.Print(f"🔴 Lỗi kết nối khi kiểm tra key VIP\n", Colors.yellow_to_red, interval=0.000000000000001)
            sleep(1)
    
    # Nếu key VIP không hợp lệ, kiểm tra key free
    if os.path.exists('Z-Matrix_key.txt'):
        with open('Z-Matrix_key.txt', 'r') as file:
            saved_key = file.read().strip()
        Write.Print(f"🔑 Đang kiểm tra key Free: {saved_key}\n", Colors.blue_to_cyan, interval=0.000000000000001)
        Check_key = requests.get(f'https://zmatrixtool.x10.mx/Api/Check_key.php?key={saved_key}').json()['data']
        
        if Check_key['message'] == "Key ĐÚNG":
            Write.Print(f"🟢 Key Free Còn Hạn!\n", Colors.green_to_yellow, interval=0.000000000000001)
            sleep(1)
            Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000001)
            time.sleep(2)
            banner()
            return  # Thoát nếu key free hợp lệ
        else:
            Write.Print(f"🔴 Key Free Hết Hạn Hoặc Không Hợp Lệ!\n", Colors.yellow_to_red, interval=0.000000000000001)
            sleep(1)
    
    # Nếu cả key VIP và key free đều không hợp lệ
    Write.Print(f"🔴 Không Tìm Thấy Key Hợp Lệ!\n", Colors.yellow_to_red, interval=0.000000000000001)
    sleep(1)
    Write.Print(f"🟢 Vui Lòng Quay Lại Tool Chính Để Lấy Key!\n", Colors.green_to_yellow, interval=0.000000000000001)
    sleep(2)
    
    banner()
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("║ Mua Key Vip Hãy Lên Shop: https://zmatrixtool.x10.mx/shop    ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("║ Nhập Vào Số [2] Để Lấy [ID DEVICE] Và Đăng Ký                ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print(">>>              CHỌN LOẠI KEY MUỐN KÍCH HOẠT:              <<<\n", Colors.green_to_yellow, interval=0.000000000000001)
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("║ [1] FREE                                                     ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("║ [2] VIP                                                      ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.blue_to_green, interval=0.000000000000001)
    loai_key = int(input(f"{trang}Chọn Loại: {vang}"))
    if loai_key == 1:
        banner()
        key()
    elif loai_key == 2:
        banner()
        check_key_vip()
    else:
        print("Lựa chọn không hợp lệ!")
        quit()

def key():
    if os.path.exists('Z-Matrix_key.txt'):
        with open('Z-Matrix_key.txt', 'r') as file:
            saved_key = file.read().strip()
        # Xác thực key từ file với Api
        Check_key = requests.get(f'https://zmatrixtool.x10.mx/Api/Check_key.php?key={saved_key}').json()['data']
        
        if Check_key['message'] == "Key ĐÚNG":
            Write.Print(f"🟢 Key Còn Hạn!\n", Colors.green_to_yellow, interval=0.000000000000000001)
            sleep(1)
            Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000000001)
            time.sleep(2)
            banner()
            with open('Z-Matrix_key.txt', 'r') as file:
                saved_key = file.read().strip()
            return
        else:
            banner()
            Write.Print(f'🔴 Key Hết Hạn!\n', Colors.red_to_purple, interval=0.000000000000000001)
            sleep(1)
            Write.Print(f'🟢 Vượt Link Lại Nhé\n', Colors.red_to_purple, interval=0.000000000000000001)
            sleep(1)
            os.system('cls' if os.name == 'nt' else 'clear')
            banner()
            Write.Print(f"\r🟢 Đang Tiến Hành Tạo Key...\n", Colors.green_to_yellow, interval=0.000000000000000001)
            time.sleep(2)
            os.system('cls' if os.name == 'nt' else 'clear')
            generate_new_key()
    else:
        generate_new_key()

def generate_new_key():
    banner()
    tao_key = requests.get('https://zmatrixtool.x10.mx/Api/Register_key.php').json()['data']
    if tao_key['status'] == "error":
        Write.Print(f"❌ {tao_key['message']}\n", Colors.red_to_purple, interval=0.000000000000000001)
        quit()
    else:
        link_key = tao_key['url']
        Write.Print(f"🟢 Link Get Key : {link_key}\n", Colors.yellow_to_red, interval=0.000000000000000001)
        nhap_key = Write.Input(f"🔑 Nhập Key Đã Lấy: ", Colors.blue_to_cyan, interval=0.000000000000000001)
        Check_key = requests.get(f'https://zmatrixtool.x10.mx/Api/Check_key.php?key={nhap_key}').json()['data']
        
        # Xác thực key
        if Check_key['message'] == "Key ĐÚNG":
            time.sleep(1)
            Write.Print(f"🟢 Key Đúng!\n", Colors.green_to_yellow, interval=0.000000000000000001)
            time.sleep(1)
            Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000000001)
            time.sleep(2)
            with open('Z-Matrix_key.txt', 'w') as file:
                file.write(nhap_key)
            banner()
            return
        else:
            Write.Print(f"🔴 Key Error!\n", Colors.yellow_to_red, interval=0.000000000000000001)
            sleep(2)
            Write.Print(f'🔴 Kiểm Tra Lại Key!\n', Colors.yellow_to_red, interval=0.000000000000000001)
            quit()

# Khóa bí mật dùng để mã hóa/giải mã XOR
SECRET_KEY = ".zmatrix_keyencode"

def xor_encrypt_decrypt(data: str, key: str) -> str:
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def encode_device_id(device_id: str) -> str:
    encrypted = xor_encrypt_decrypt(device_id, SECRET_KEY)
    return base64.b64encode(encrypted.encode()).decode()

def decode_device_id(encoded: str) -> str:
    try:
        decoded_bytes = base64.b64decode(encoded)
        decrypted = xor_encrypt_decrypt(decoded_bytes.decode(), SECRET_KEY)
        return decrypted
    except:
        return "INVALID_ID"

def get_device_id():
    base_folder = '_FOLDER IMPORTANT_'
    if not os.path.exists(base_folder):
        os.makedirs(base_folder)
    
    config_path = os.path.join(base_folder, 'error_log.zip')
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
        filename = config['file']
    else:
        filename = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + '.zip'
        config = {'file': filename}
        with open(config_path, 'w') as f:
            json.dump(config, f)
    
    device_id_file = os.path.join(base_folder, filename)
    
    if not os.path.exists(device_id_file):
        # Tạo ID mới
        big_number = str(random.randint(10**19, 10**20 - 1))
        random_id = f"Z-Matrix_{big_number[:8]}"
        
        # Mã hóa và ghi file
        encoded_id = encode_device_id(random_id)
        with open(device_id_file, 'w') as f:
            f.write(encoded_id)
        return random_id
    else:
        # Đọc và giải mã
        with open(device_id_file, 'r') as f:
            encoded_id = f.read().strip()
        return decode_device_id(encoded_id)

def check_key_vip():
    hwid = get_device_id()
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print(f"║ ID DEVICE: {get_device_id()}                                 ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.blue_to_green, interval=0.000000000000001)
    
    if os.path.exists('Z-Matrix_key_vip.txt'):
        with open('Z-Matrix_key_vip.txt', 'r') as file:
            key_vippro = file.read().strip()
        response = requests.get(f'https://zmatrixtool.x10.mx/shop/data/check_key_vip.php?key={key_vippro}&hwid={hwid}', timeout=5)
        response.raise_for_status()
        data = response.json()
        if 'message' in data and data['message'] == "Key hợp lệ.":
            Write.Print(f"🟢 Key Còn Hạn!\n", Colors.green_to_yellow, interval=0.000000000000000001)
            sleep(1)
            Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000000001)
            time.sleep(2)
            banner()
            with open('Z-Matrix_key_vip.txt', 'r') as file:
                key_vippro = file.read().strip()
            return
        else:
            Write.Print(f"🔴 Key Error hoặc hết hạn!\n", Colors.yellow_to_red, interval=0.000000000000000001)
            time.sleep(2)
            Write.Print(f'🔴 Kiểm Tra Lại Key!\n', Colors.yellow_to_red, interval=0.000000000000000001)
            with open('Z-Matrix_key_vip.txt', 'w') as file:
                pass
    
    banner()
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print(f"║ ID THIẾT BỊ: {get_device_id()}                               ║\n", Colors.blue_to_green, interval=0.000000000000001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.blue_to_green, interval=0.000000000000001)
    key_vippro = Write.Input(f"🔑 Nhập Key Đã Mua: ", Colors.blue_to_cyan, interval=0.000000000000000001)
    try:
        response = requests.get(f'https://zmatrixtool.x10.mx/shop/data/check_key_vip.php?key={key_vippro}&hwid={hwid}', timeout=5)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        Write.Print(f"🔴 Lỗi kết nối hoặc HTTP: {e}\n", Colors.yellow_to_red, interval=0.000000000000000001)
        quit()
    except ValueError:
        Write.Print(f"🔴 Phản hồi không phải JSON hợp lệ.\n", Colors.yellow_to_red, interval=0.000000000000000001)
        quit()
    
    if 'message' in data and data['message'] == "Key hợp lệ.":
        time.sleep(1)
        Write.Print(f"🟢 Key Đúng!\n", Colors.green_to_yellow, interval=0.000000000000000001)
        time.sleep(1)
        Write.Print(f"🟢 Đang Kết Nối Đến Server...\n", Colors.green_to_yellow, interval=0.000000000000000001)
        time.sleep(2)
        banner()
        with open('Z-Matrix_key_vip.txt', 'w') as file:
            file.write(key_vippro)
        with open('Z-Matrix_key_vip.txt', 'r') as file:
            key_vippro = file.read().strip()
    else:
        Write.Print(f"🔴 Key Error hoặc hết hạn!\n", Colors.yellow_to_red, interval=0.000000000000000001)
        time.sleep(2)
        Write.Print(f'🔴 Kiểm Tra Lại Key!\n', Colors.yellow_to_red, interval=0.000000000000000001)
        with open('Z-Matrix_key_vip.txt', 'w') as file:
            pass
        quit()

def run():
    print(f"{trang}Trạng Thái Server: {luc}ONLINE")
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("║                         LOGIN GOLIKE                         ║\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.green_to_yellow, interval=0.0001)
    
    # Nhập auth
    try:
        Authorization = open("Authorization.txt", "x")
    except:
        pass
    Authorization = open("Authorization.txt", "r")
    author = Authorization.read()
    if author == "":
        author = input(f"{lam}Nhập AUTHORIZATION{trang}: {vang}")
        Authorization = open("Authorization.txt", "w")
        Authorization.write(author)
    else:
        select = input(f"""{hong}Nhấn {trang}Enter {hong}Hoặc Nhập {vang}AUTHORIZATION {hong}Để Vào Acc {lam}Golike {hong}Khác{trang}: 
""")
        if select != "":
            author = select
            Authorization = open("Authorization.txt", "w")
            Authorization.write(author)
    Authorization.close()
    
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("║                     DANH SÁCH ACC TIKTOK                     ║\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.green_to_yellow, interval=0.0001)
    
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=utf-8',
        'Authorization': author,
        't': 'VFZSak1VMVVRWGhQVkZFMVRWRTlQUT09',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        'Referer': 'https://app.golike.net/account/manager/tiktok',
    }

    scraper = cloudscraper.create_scraper()
    
    def chonacc():
        def loading_animation(stop_event):
            dots = [".", "..", "..."]
            while not stop_event.is_set():
                for dot in dots:
                    print(f"\r{hong}Đang tải danh sách tài khoản{dot}   ", end="", flush=True)
                    time.sleep(0.5)
                    if stop_event.is_set():
                        break
            print("\r" + " " * 50 + "\r", end="")  # Xóa dòng loading

        stop_event = threading.Event()
        loading_thread = threading.Thread(target=loading_animation, args=(stop_event,), daemon=True)
        loading_thread.start()

        json_data = {}
        try:
            response = scraper.get(
                'https://gateway.golike.net/api/tiktok-account',
                headers=headers,
                json=json_data
            ).json()
            stop_event.set()  # Dừng animation khi tải xong
            loading_thread.join()  # Đợi thread loading kết thúc
            print(f"{lam}Đã load xong!", end="", flush=True)  # In dòng thông báo
            time.sleep(0.5)                                      # Chờ 1 giây
            print("\r" + " " * 50 + "\r", end="", flush=True)  # Xóa dòng
            return response
        except Exception:
            stop_event.set()  # Dừng animation nếu có lỗi
            loading_thread.join()  # Đợi thread loading kết thúc
            Write.Print(f"{red}Lỗi khi tải danh sách tài khoản!\n", Colors.red_to_purple, interval=0.0001)
            sys.exit()
    def nhannv(account_id):
        try:
            params = {
                'account_id': account_id,
                'data': 'null',
            }
            response = scraper.get(
                'https://gateway.golike.net/api/advertising/publishers/tiktok/jobs',
                headers=headers,
                params=params,
                json={}
            )
            return response.json()
        except Exception:
            sys.exit()
    
    def hoanthanh(ads_id, account_id):
        try:
            json_data = {
                'ads_id': ads_id,
                'account_id': account_id,
                'async': True,
                'data': None,
            }
            response = scraper.post(
                'https://gateway.golike.net/api/advertising/publishers/tiktok/complete-jobs',
                headers=headers,
                json=json_data,
                timeout=6
            )
            return response.json()
        except Exception:
            sys.exit()
    
    def baoloi(ads_id, object_id, account_id, loai):
        try:
            json_data1 = {
                'description': 'Tôi đã làm Job này rồi',
                'users_advertising_id': ads_id,
                'type': 'ads',
                'provider': 'tiktok',
                'fb_id': account_id,
                'error_type': 6,
            }
            scraper.post('https://gateway.golike.net/api/report/send', headers=headers, json=json_data1)
            json_data2 = {
                'ads_id': ads_id,
                'object_id': object_id,
                'account_id': account_id,
                'type': loai,
            }
            scraper.post(
                'https://gateway.golike.net/api/advertising/publishers/tiktok/skip-jobs',
                headers=headers,
                json=json_data2,
            )
        except Exception:
            sys.exit()
    
    # Gọi chọn tài khoản một lần và xử lý lỗi nếu có
    chontktiktok = chonacc()
    
    def dsacc():
        if chontktiktok.get("status") != 200:
            print("\033[1;31m Authorization Hoăc T Sai ")
            quit()
        for i in range(len(chontktiktok["data"])):
            print(f'{lam}[{trang}{i+1}{lam}] {vang}{chontktiktok["data"][i]["nickname"]} {trang}STATUS:\033[1;32m Hoạt Động')
    
    dsacc()
    
    # Chọn tài khoản TikTok
    while True:
        try:
            luachon = int(input(f"{trang}- {lam}Chọn Tài Khoản {trang}TikTok {lam}Cần Chạy{trang}: {vang}"))
            if 1 <= luachon <= len(chontktiktok["data"]):
                account_id = chontktiktok["data"][luachon - 1]["id"]
                break
            else:
                print("\033[1;31m🚫 Tài Khoản Không Tồn Tại Trong Danh Sách, Nhập Lại..")
        except ValueError:
            print("\033[1;31m Sai Định Dạng! Vui Lòng Nhập Số.\033[0m", end='', flush=True)
            time.sleep(1)  # Chờ 1 giây
            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Ghi đè dòng bằng khoảng trắng rồi quay về đầu dòng

    
    # Nhập delay
    while True:
        try:
            delay = int(input(f"{trang}- {lam}Delay{trang}: {vang}"))
            break
        except ValueError:
            print("\033[1;31m Sai Định Dạng! Vui Lòng Nhập Số.\033[0m", end='', flush=True)
            time.sleep(1)  # Chờ 1 giây
            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Ghi đè dòng bằng khoảng trắng rồi quay về đầu dòng

    
    # Nhập số lần thất bại để đổi acc
    while True:
        try:
            doiacc = int(input(f"{trang}- {lam}Thất Bại Bao Nhiêu Lần Thì Đổi {trang}Acc: {vang}"))
            break
        except:
            print("\033[1;31m Sai Định Dạng! Vui Lòng Nhập Số.\033[0m", end='', flush=True)
            time.sleep(1)  # Chờ 1 giây
            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Ghi đè dòng bằng khoảng trắng rồi quay về đầu dòng

    # Bỏ qua job < 20đ
    boqua_job_duoi_20 = False

    while True:
        chon_boqua = input(f"{trang}- {hong}Bỏ Qua {trang}Job {hong}Dưới {vang}20đ {trang}(y/n): {vang}").lower().strip()
        if chon_boqua == 'y':
            print(f"{lam}Đã Loại Bỏ Job {hong}< {vang}20đ")
            boqua_job_duoi_20 = True
            break
        elif chon_boqua == 'n':
            boqua_job_duoi_20 = False
            break
        else:
            print(f"{red} Sai Định Dạng! Vui Lòng Nhập {trang}y {red}hoặc {trang}n\033[0m")

    
    Write.Print(">>>                 CHỌN NHIỆM VỤ MUỐN CHẠY:                 <<<\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.white, interval=0.0001)
    Write.Print("║ [1] FOLLOW                                                   ║\n", Colors.white, interval=0.0001)
    Write.Print("║ [2] TIM                                                      ║\n", Colors.white, interval=0.0001)
    Write.Print("║ [3] ALL                                                      ║\n", Colors.white, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.white, interval=0.0001)
    
    while True:
        try:
            loai_nhiem_vu = int(input(f"{lam}Chọn Loại Nhiệm Vụ{trang}: {vang}"))
            if loai_nhiem_vu in [1, 2, 3]:
                break
            else:
                print("\033[1;31m⚠ Vui Lòng Chọn Số Từ 1 Đến 3!")
        except ValueError:
            print("\033[1;31m Sai Định Dạng! Vui Lòng Nhập Số.\033[0m", end='', flush=True)
            time.sleep(1)  # Chờ 1 giây
            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Ghi đè dòng bằng khoảng trắng rồi quay về đầu dòng
    x_like, y_like, x_follow, y_follow = None, None, None, None
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("║                       ADB AUTOMATICALLY                      ║\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.white, interval=0.0001)
    Write.Print("║ [1] CÓ                                                       ║\n", Colors.white, interval=0.0001)
    Write.Print("║ [2] KHÔNG                                                    ║\n", Colors.white, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.white, interval=0.0001)
    
    adbyn = input(f"{lam}Nhập Lựa Chọn{trang}: {vang}")
    
    def in_mau(text, color=Fore.WHITE, bold=True):
        style = Style.BRIGHT if bold else Style.NORMAL
        return f"{style}{color}{text}{Style.RESET_ALL}"
    
    if adbyn == "1":
        def setup_adb():
            config_file = "config_adb.txt"
            like_coords_file = "toa_do_tim.txt"
            follow_coords_file = "toa_do_follow.txt"
            
            # Nhập IP và port ADB
            Write.Print("════════════════════════════════════════════════════════\n", Colors.green_to_yellow, interval=0.0001)
            print("\033[1;36mXem Video Hướng Dẫn Kết Nối ADB")
            video = requests.get('https://zmatrixtool.x10.mx/Api/Video.php').text
            print(f"{vang}Link video: {xduong}{video}")
            ip = input(f"{vang}Nhập IP Của Thiết Bị Ví Dụ \033[1;37m(192.168.x.x): \033[1;36m")
            adb_port = input(f"{vang}Nhập Port Của Thiết Bị Ví Dụ \033[1;37m(58219): \033[1;36m")
            
            # Kiểm tra và đọc tọa độ từ file nếu tồn tại
            x_like, y_like, x_follow, y_follow = None, None, None, None
            
            if os.path.exists(like_coords_file):
                with open(like_coords_file, "r") as f:
                    coords = f.read().split("|")
                    if len(coords) == 2:
                        x_like, y_like = coords
                        print(f"\033[1;32mĐã Tìm Thấy Tọa Độ Nút Tim: {vang}X={lam}{x_like}, {vang}Y={lam}{y_like}")
            
            if os.path.exists(follow_coords_file):
                with open(follow_coords_file, "r") as f:
                    coords = f.read().split("|")
                    if len(coords) == 2:
                        x_follow, y_follow = coords
                        print(f"\033[1;32mĐã Tìm Thấy Tọa Độ Nút Follow: {vang}X={lam}{x_follow}, {vang}Y={lam}{y_follow}")
            
            if not os.path.exists(config_file):
                print("\033[1;36mLần Đầu Chạy, Nhập Mã Ghép Nối (6 Số) Và Port Ghép Nối.\033[0m")
                pair_code = input(f"{vang}Nhập Mã Ghép Nối 6 Số Ví Dụ \033[1;37m(317924): \033[1;36m")
                pair_port = input(f"{vang}Nhập Port Của Thiết Bị Ví Dụ \033[1;37m(32186): \033[1;36m")
                
                with open(config_file, "w") as f:
                    f.write(f"{pair_code}|{pair_port}")
            else:
                with open(config_file, "r") as f:
                    pair_code, pair_port = [s.strip() for s in f.read().split("|")]
            
            print("\n\033[1;32m Đang Ghép Nối Với Thiết Bị\033[0m")
            os.system(f"adb pair {ip}:{pair_port} {pair_code}")
            time.sleep(2)
            
            print("\033[1;36m Đang Kết Nối ADB\033[0m")
            os.system(f"adb connect {ip}:{adb_port}")
            time.sleep(2)
            
            devices = os.popen("adb devices").read()
            if ip not in devices:
                print(f"{Fore.RED} Kết Nối Thất Bại{Fore.WHITE}")
                exit()
            
            # Yêu cầu nhập tọa độ nếu chưa có
            Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.green_to_yellow, interval=0.0001)
            Write.Print("║                      NHẬP TỌA ĐỘ CÁC NÚT                     ║\n", Colors.green_to_yellow, interval=0.0001)
            Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.green_to_yellow, interval=0.0001)
            
            if loai_nhiem_vu in [1, 3] and (x_follow is None or y_follow is None):
                x_follow = input(f"{vang}Nhập Tọa Độ \033[1;37mX {vang}Của Nút Follow: {vang}")
                y_follow = input(f"{vang}Nhập Tọa Độ \033[1;37mY {vang}Của Nút Follow: {vang}")
                with open(follow_coords_file, "w") as f:
                    f.write(f"{x_follow}|{y_follow}")
            
            if loai_nhiem_vu in [2, 3] and (x_like is None or y_like is None):
                x_like = input(f"{vang}Nhập Tọa Độ \033[1;37mX {vang}Của Nút tim: {vang}")
                y_like = input(f"{vang}Nhập Tọa Độ \033[1;37mY {vang}Của Nút tim: {vang}")
                with open(like_coords_file, "w") as f:
                    f.write(f"{x_like}|{y_like}")
            
            return x_like, y_like, x_follow, y_follow
        
        # Khi gọi hàm setup_adb()
        x_like, y_like, x_follow, y_follow = setup_adb()
    elif adbyn == "2":
        pass
    
    dem = 0
    tong = 0
    checkdoiacc = 0
    dsaccloi = []
    accloi = ""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner()
    Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("║                       START EARN MONEY                       ║\n", Colors.green_to_yellow, interval=0.0001)
    Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.green_to_yellow, interval=0.0001)
    
    while True:
        if checkdoiacc == doiacc:
            dsaccloi.append(chontktiktok["data"][luachon - 1]["nickname"])
            Write.Print("╔══════════════════════════════════════════════════════════════╗\n", Colors.red_to_purple, interval=0.0001)
            print(f"\033[1;31m Acc Tiktok {dsaccloi} gặp vấn đề ")
            Write.Print("╚══════════════════════════════════════════════════════════════╝\n", Colors.red_to_purple, interval=0.0001)
            dsacc()
            while True:
                try:
                    Write.Print("════════════════════════════════════════════════════════\n", Colors.green_to_yellow, interval=0.0001)
                    luachon = int(input(f"{vang}- {lam}Chọn Tài Khoản {trang}TikTok {lam}Cần Chạy{trang}: {vang}"))
                    while luachon > len((chontktiktok)["data"]):
                        luachon = int(input("\033[1;31m🚫 Tài Khoản Không Tồn Tại Trong Danh Sách, Vui Lòng Nhập Lại:"))
                    account_id = chontktiktok["data"][luachon - 1]["id"]
                    checkdoiacc = 0
                    os.system('cls' if os.name == 'nt' else 'clear')
                    for h in banner:
                        print(h, end="")
                    break
                except:
                    print("\033[1;31m Sai Định Dạng! Vui Lòng Nhập Số.\033[0m", end='', flush=True)
            time.sleep(1)  # Chờ 1 giây
            sys.stdout.write('\r' + ' ' * 50 + '\r')  # Ghi đè dòng bằng khoảng trắng rồi quay về đầu dòng

        print(f'{hong} Đang {lam}Chuyển {trang}Job', end="\r")
        max_retries = 3
        retry_count = 0
        nhanjob = None
        
        while retry_count < max_retries:
            try:
                nhanjob = nhannv(account_id)
                if nhanjob and nhanjob.get("status") == 200 and nhanjob["data"].get("link") and nhanjob["data"].get("object_id"):
                    break
                else:
                    retry_count += 1
                    time.sleep(2)
            except Exception as e:
                retry_count += 1
                time.sleep(1)
        
        if not nhanjob or retry_count >= max_retries:
            continue
        
        ads_id = nhanjob["data"]["id"]
        link = nhanjob["data"]["link"]
        object_id = nhanjob["data"]["object_id"]
        job_type = nhanjob["data"]["type"]
        
        # Bỏ qua job < 20đ
        price_after = nhanjob["data"].get("price_per_after_cost", 0)
        if boqua_job_duoi_20 and price_after < 20:
            print(f"{lam}Bỏ qua job {hong}< {vang}20đ")
            baoloi(ads_id, object_id, account_id, job_type)
            time.sleep(1.5)
            continue
        
        if job_type == "follow":
            data = nhanjob["data"]
            if data["count_success"] <= 10 and data["count_is_run"] <= 10 and data["viewer"] < 100:
                baoloi(ads_id, object_id, account_id, job_type)
                time.sleep(2)
                continue
        
        # Kiểm tra loại nhiệm vụ
        if (loai_nhiem_vu == 1 and job_type != "follow") or \
           (loai_nhiem_vu == 2 and job_type != "like") or \
           (job_type not in ["follow", "like"]):
            baoloi(ads_id, object_id, account_id, job_type)
            continue
        
        # Mở link và kiểm tra lỗi
        try:
            if adbyn == "1":
                os.system(f'adb shell am start -a android.intent.action.VIEW -d "{link}" > /dev/null 2>&1')
            else:
                subprocess.run(["termux-open-url", link])
            
            for remaining in range(3, 0, -1):
                time.sleep(1)
            print("\r" + " " * 30 + "\r", end="")
        
        except Exception as e:
            baoloi(ads_id, object_id, account_id, job_type)
            continue
        
        # Thực hiện thao tác ADB
        if job_type == "like" and adbyn == "1" and x_like and y_like:
            os.system(f"adb shell input tap {x_like} {y_like}")
        elif job_type == "follow" and adbyn == "1" and x_follow and y_follow:
            os.system(f"adb shell input tap {x_follow} {y_follow}")
        
        # Đếm ngược delay
        for remaining_time in range(delay, -1, -1):
            color = "\033[1;36m" if remaining_time % 2 == 0 else "\033[38;2;255;192;203m"
            print(f"\r{color}Đang Làm Nhiệm Vụ {remaining_time:2d} giây   ", end="", flush=True)
            time.sleep(1)
        
        print("\r                          \r", end="")
        print(f"{hong}Đang Nhận Tiền    ", end="\r")
        
        # Hoàn thành job
        max_attempts = 2
        attempts = 0
        nhantien = None
        while attempts < max_attempts:
            try:
                nhantien = hoanthanh(ads_id, account_id)
                if nhantien and nhantien.get("status") == 200:
                    break
            except:
                pass
            attempts += 1
        
        if nhantien and nhantien.get("status") == 200:
            dem += 1
            tien = nhantien["data"]["prices"]
            tong += tien
            local_time = time.localtime()
            hour = local_time.tm_hour
            minute = local_time.tm_min
            second = local_time.tm_sec
            h = hour
            m = minute
            s = second
            if hour < 10:
                h = "0" + str(hour)
            if minute < 10:
                m = "0" + str(minute)
            if second < 10:
                s = "0" + str(second)
            
            chuoi = (
                f"\033[1;37m[\033[38;2;135;206;250mTime: {h}:{m}:{s}\033[1;37m]"  # time màu light sky blue
                f" \033[1;37m[{vang}{dem}\033[1;37m]"                            # Số thứ tự đỏ
                f" \033[1;37m[\033[1;32mDone\033[1;37m]"                           # Done xanh lá
                f" \033[1;37m[\033[38;2;0;191;255m{job_type}\033[1;37m]"            # job_type màu Deep Sky Blue
                f" \033[1;37m[{vang}+{tien}\033[1;37m]"                        # tiền màu vàng sáng
                f" \033[1;37m[\033[38;2;255;215;0mTổng: {tong}\033[1;37m]"          # Tổng tiền màu vàng gold
            )
            
            print("                                                    ", end="\r")
            print(chuoi)
            time.sleep(0.7)
            checkdoiacc = 0
        else:
            try:
                baoloi(ads_id, object_id, account_id, nhanjob["data"]["type"])
                print("                                              ", end="\r")
                print("\033[1;37m Bỏ Qua Nhiệm Vụ ", end="\r")
                sleep(1)
                checkdoiacc += 1
            except:
                pass
    
def main():
    try:
        while True:
            Server()
            banner()
            select_key()
            run()
            return None
    except KeyboardInterrupt:
        Write.Print(f"\nCảm Ơn Bạn Đã Sử Dụng Tool!\n", Colors.blue_to_cyan, interval=0.000000000000000001)
        sys.exit(0)
if __name__ == "__main__":
    main()  

#!/usr/bin/env python3
import requests
import json
import hashlib
import random
import uuid
import os
import time
import datetime
import struct
# ======================【新增：进度条函数】======================
def progress_bar_error(total=30, delay=0.04):
    """卡密错误：带❌红色叉号进度条"""
    RED = '\033[91m'
    RESET = '\033[0m'
    print(f"\n{RED}⚠️ 卡密校验失败 {RESET}")
    for i in range(total + 1):
        bar = "❌" * i + " " * (total - i)
        percent = int((i / total) * 100)
        print(f"\r{RED}[{bar}] {percent}% 验证失败{RESET}", end="", flush=True)
        time.sleep(delay)
    print("\n")
def progress_bar_tech_success(total=35, delay=0.025):
    """登录成功 科技风蓝色进度条"""
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    tech_char = "▓"
    print(f"\n{CYAN}🔐 卡密校验通过，正在载入工具箱核心模块{RESET}")
    for i in range(total + 1):
        bar = tech_char * i + "░" * (total - i)
        percent = int((i / total) * 100)
        print(f"\r{BLUE}[{bar}] {percent}% Loading System...{RESET}", end="", flush=True)
        time.sleep(delay)
    print(f"\n{CYAN}✅ 系统加载完成！{RESET}\n")
# ==============================================================
def get_device_id(file_path=".imei"):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            device_id = f.read().strip()
    else:
        device_id = str(uuid.uuid1())
        with open(file_path, "w") as f:
            f.write(device_id)
    return device_id
def sha1_rotate_left(n, b):
    """循环左移"""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
def sha1_pad_message(message):
    """对消息进行填充"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    length = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (length + 1) % 64) % 64)
    message += struct.pack('>Q', length * 8)
    return message
def za51e1fc6b6a47fe701277cd09ec71299(message):
    """计算 SHA-1 哈希值"""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    message = sha1_pad_message(message)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j*4:j*4+4])[0]
        for j in range(16, 80):
            w[j] = sha1_rotate_left(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a, b, c, d, e = h0, h1, h2, h3, h4
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (sha1_rotate_left(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = sha1_rotate_left(b, 30)
            b = a
            a = temp
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
# ==================== SHA-256 实现 ====================
def sha256_rotate_right(n, b):
    """循环右移"""
    return ((n >> b) | (n << (32 - b))) & 0xffffffff
def sha256_pad_message(message):
    """对消息进行填充"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    length = len(message)
    message += b'\x80'
    message += b'\x00' * ((64 - (length + 9) % 64) % 64)
    message += struct.pack('>Q', length * 8)
    return message
def l321cb04d2cbe762b5b8bc83ca0f9ffa3(message):
    """计算 SHA-256 哈希值"""
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    message = sha256_pad_message(message)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j*4:j*4+4])[0]
        for j in range(16, 64):
            s0 = sha256_rotate_right(w[j-15], 7) ^ sha256_rotate_right(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = sha256_rotate_right(w[j-2], 17) ^ sha256_rotate_right(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff
        a, b, c, d, e, f, g, h_temp = h
        for j in range(64):
            S1 = sha256_rotate_right(e, 6) ^ sha256_rotate_right(e, 11) ^ sha256_rotate_right(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h_temp + S1 + ch + k[j] + w[j]) & 0xffffffff
            S0 = sha256_rotate_right(a, 2) ^ sha256_rotate_right(a, 13) ^ sha256_rotate_right(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff
            h_temp = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + h_temp) & 0xffffffff
    return ''.join(format(x, '08x') for x in h)
def d6a728fe7caeb6fc6b94882f5abe5f01e(data: str) -> str:
    m = hashlib.md5()
    m.update(data.encode('utf-8'))
    return m.hexdigest()
def l09aaacf40a230bd1e7cacecf8476a7dd(data, key):
    def ksa(key):
        key_len = len(key)
        schedule = list(range(256))
        j = 0
        for i in range(256):
            j = (j + schedule[i] + key[i % key_len]) % 256
            schedule[i], schedule[j] = schedule[j], schedule[i]
        return schedule
    def prga(schedule, data_len):
        i = j = 0
        stream = []
        for _ in range(data_len):
            i = (i + 1) % 256
            j = (j + schedule[i]) % 256
            schedule[i], schedule[j] = schedule[j], schedule[i]
            stream.append(schedule[(schedule[i] + schedule[j]) % 256])
        return stream
    def process(data, key):
        schedule = ksa(key)
        stream = prga(schedule, len(data))
        return bytes([d ^ s for d, s in zip(data, stream)])
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    return process(data, key).decode('utf-8')
def gfdb766be1aba375c731fe23450bc2cb4(data, key):
    def ksa(key):
        key_len = len(key)
        schedule = list(range(256))
        j = 0
        for i in range(256):
            j = (j + schedule[i] + key[i % key_len]) % 256
            schedule[i], schedule[j] = schedule[j], schedule[i]
        return schedule
    def prga(schedule, data_len):
        i = j = 0
        stream = []
        for _ in range(data_len):
            i = (i + 1) % 256
            j = (j + schedule[i]) % 256
            schedule[i], schedule[j] = schedule[j], schedule[i]
            stream.append(schedule[(schedule[i] + schedule[j]) % 256])
        return stream
    def process(data, key):
        schedule = ksa(key)
        stream = prga(schedule, len(data))
        return bytes([d ^ s for d, s in zip(data, stream)])
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    return process(data, key)
def za8bd039bb6482b745385b8cb597bf353(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise ValueError("Input must be of type str or bytes")
    return ''.join(f'{byte:02x}' for byte in data)
def y0423df98fe0b06646edd0044ba7b7225(hex_str):
    return bytes.fromhex(hex_str)
def j4d388d13c331f3d2ea89197910813f96(data: str) -> str:
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    byte_data = data.encode('utf-8')
    binary_data = ''.join(f'{byte:08b}' for byte in byte_data)
    base64_str = ""
    for i in range(0, len(binary_data), 6):
        chunk = binary_data[i:i+6]
        chunk = chunk.ljust(6, '0')
        index = int(chunk, 2)
        base64_str += base64_chars[index]
    while len(base64_str) % 4 != 0:
        base64_str += '='
    return base64_str
def c425684234ce4d5f3b79977925f58a7de(data: str) -> str:
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    binary_data = ""
    data = data.rstrip('=')
    for c in data:
        index = base64_chars.index(c)
        binary_data += f'{index:06b}'
    byte_array = bytearray()
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            byte_array.append(int(byte, 2))
    return byte_array.decode('utf-8')
def r9cfa1eeafdec2515efcc0d3732a79ea0(data: str, base64_chars: str) -> str:
    byte_data = data.encode('utf-8')
    binary_data = ''.join(f'{byte:08b}' for byte in byte_data)
    base64_str = ""
    for i in range(0, len(binary_data), 6):
        chunk = binary_data[i:i+6]
        chunk = chunk.ljust(6, '0')
        index = int(chunk, 2)
        base64_str += base64_chars[index]
    while len(base64_str) % 4 != 0:
        base64_str += '='
    return base64_str
def k78cab93fdde6f0a901624387aaa1741b(data: str, base64_chars: str) -> str:
    binary_data = ""
    data = data.rstrip('=')
    for c in data:
        index = base64_chars.index(c)
        binary_data += f'{index:06b}'
    byte_array = bytearray()
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            byte_array.append(int(byte, 2))
    return byte_array.decode('utf-8')
WEIURL = "http://wy.llua.cn/v2/"
currentVersion = "1.1"

# ============ 云更新模块 开始 ============
import sys
import subprocess

UPDATE_VERSION_URL = (
    "https://example.com/version.json"
)
UPDATE_ENABLED = True


def _ver_tuple(v):
    parts = []
    for p in str(v).split("."):
        n = "".join(c for c in p if c.isdigit())
        parts.append(int(n) if n else 0)
    return tuple(parts)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()


def cloud_update(cur_ver):
    if not UPDATE_ENABLED:
        return False
    try:
        script_path = os.path.abspath(__file__)
    except NameError:
        return False
    script_dir = os.path.dirname(script_path)
    script_name = os.path.basename(script_path)

    print("\n[云更新] 正在检查更新...")

    try:
        r = requests.get(UPDATE_VERSION_URL, timeout=10)
        r.raise_for_status()
        info = r.json()
    except Exception as e:
        print("[云更新] 无法连接服务器，跳过: " + str(e))
        return False

    remote_ver = str(info.get("version", "0.0.0"))
    url = info.get("url", "")
    sha = info.get("sha256", "")
    log = info.get("changelog", "")

    try:
        if _ver_tuple(remote_ver) <= _ver_tuple(cur_ver):
            print("[云更新] 已是最新版本 (v" + cur_ver + ")")
            return False
    except Exception:
        return False

    print("[云更新] 发现新版本 v" + remote_ver + "（当前 v" + cur_ver + "）")
    if log:
        print("[云更新] 更新内容: " + log)

    if not url:
        print("[云更新] 缺少下载地址")
        return False

    tmp_new = os.path.join(script_dir, script_name + ".new")
    try:
        print("[云更新] 开始下载...")
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))
            done = 0
            with open(tmp_new, "wb") as f:
                for chunk in r.iter_content(8192):
                    if not chunk:
                        continue
                    f.write(chunk)
                    done += len(chunk)
                    if total > 0:
                        pct = done * 100 // total
                        bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
                        print("\r  [" + bar + "] " + str(pct) + "%", end="", flush=True)
        print()
    except Exception as e:
        print("[云更新] 下载失败: " + str(e))
        if os.path.exists(tmp_new):
            try:
                os.remove(tmp_new)
            except Exception:
                pass
        return False

    if sha:
        try:
            actual = _sha256_file(tmp_new)
            if actual.lower() != sha.lower():
                print("[云更新] SHA-256 校验失败")
                os.remove(tmp_new)
                return False
            print("[云更新] 文件校验通过")
        except Exception as e:
            print("[云更新] 校验异常: " + str(e))
            try:
                os.remove(tmp_new)
            except Exception:
                pass
            return False

    old_path = script_path + ".old"
    try:
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except Exception:
                pass
        if sys.platform == "win32":
            os.rename(script_path, old_path)
            os.rename(tmp_new, script_path)
        else:
            os.replace(tmp_new, script_path)
    except Exception as e:
        print("[云更新] 替换文件失败: " + str(e))
        return False

    print("[云更新] 更新成功，正在重启...")
    try:
        subprocess.Popen([sys.executable, script_path], cwd=script_dir)
    except Exception as e:
        print("[云更新] 重启失败: " + str(e))
        return True

    try:
        if sys.platform == "win32":
            subprocess.Popen(
                'ping 127.0.0.1 -n 3 >nul & del /f /q "' + old_path + '"',
                shell=True,
                creationflags=0x08000000
            )
        else:
            os.remove(old_path)
    except Exception:
        pass

    return True


if cloud_update(currentVersion):
    sys.exit(0)
# ============ 云更新模块 结束 ============
notice_data = requests.post(WEIURL + "b3faecfe0dc7db6db96f804bf55663b3",za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(za8bd039bb6482b745385b8cb597bf353("id=UUpIzeuPgWG"))),"zTfAxXRuP4bwGrtFjByvCai/W+sJI2Yheg9o1LOK7ME6ZV508n3qkcHNUdlDSmQp")),"UTpgwvtbRj43/OxMn+k6qJPIa0FouDSL2EhG79VHmWeNCrBZzXlsKiA8cYydQ5f1")),"fL0cj/6k5WQzust4hagITDmYdEGwFUNKV3Jnxe71XRorS9p2AyHMiBCOb+lZq8vP"))))
if notice_data.status_code == 200:
    notice_json = json.loads(l09aaacf40a230bd1e7cacecf8476a7dd(y0423df98fe0b06646edd0044ba7b7225(notice_data.text),"gc361eee65416e08f59"))
    if notice_json["code"] == 30072:
        print("系统公告:")
        print(notice_json["msg"]["app_gg"])
    else:
        print(notice_json["msg"])
else:
    print("网络异常")
print("\n")
print("正在检查更新...")
ini_data = requests.post(WEIURL + "b3faecfe0dc7db6db96f804bf55663b3",za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(za8bd039bb6482b745385b8cb597bf353("id=b9aFOr5g7xP"))),"zTfAxXRuP4bwGrtFjByvCai/W+sJI2Yheg9o1LOK7ME6ZV508n3qkcHNUdlDSmQp")),"UTpgwvtbRj43/OxMn+k6qJPIa0FouDSL2EhG79VHmWeNCrBZzXlsKiA8cYydQ5f1")),"fL0cj/6k5WQzust4hagITDmYdEGwFUNKV3Jnxe71XRorS9p2AyHMiBCOb+lZq8vP"))))
if ini_data.status_code == 200:
    ini_json = json.loads(l09aaacf40a230bd1e7cacecf8476a7dd(y0423df98fe0b06646edd0044ba7b7225(ini_data.text),"gc361eee65416e08f59"))
    if ini_json["code"] == 39658:
        if ini_json["msg"]["version"] == currentVersion:
            print("已是最新版本")
        else:
            print("有新版本")
            print("当前版本:" + currentVersion)
            print("最新版本:" + ini_json["msg"]["version"])
            print("更新内容:" + ini_json["msg"]["updateshow"])
            print("更新地址:" + ini_json["msg"]["updateurl"])
            if ini_json["msg"]["updatemust"] == "y":
                print("本次更新为强制更新，请更新后使用！")
                exit()
    else:
        print(ini_json["msg"])
else:
    print("网络异常")
print("\n")
while True:
    i3ba1b4e7771dcc2354c69c519c864e18 = input("请输入卡密:")
    q23a5d41f0d00c7cac3b7ace77d66ec67 = get_device_id()
    u40fa45f4a0ccec32f6ec5795ba6f0ba0 = int(time.time())
    n1d541db54bc09406bd01a916d8e9f2a0 = random.randint(100000, 999999)
    wc7f77547c46e1d23dd20821b58d8165b = d6a728fe7caeb6fc6b94882f5abe5f01e("kami=" + i3ba1b4e7771dcc2354c69c519c864e18 + "&markcode=" + q23a5d41f0d00c7cac3b7ace77d66ec67 + "&t=" + str(u40fa45f4a0ccec32f6ec5795ba6f0ba0) + "&i9af372c9fdfc7e9ead0f")
    i8c59691950f4145cd5136e08fdac895a = requests.post(WEIURL + "b3faecfe0dc7db6db96f804bf55663b3",za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(r9cfa1eeafdec2515efcc0d3732a79ea0(za8bd039bb6482b745385b8cb597bf353(j4d388d13c331f3d2ea89197910813f96(za8bd039bb6482b745385b8cb597bf353("id=m8z82MdINCt&kami=" + i3ba1b4e7771dcc2354c69c519c864e18 + "&markcode=" + q23a5d41f0d00c7cac3b7ace77d66ec67 + "&t=" + str(u40fa45f4a0ccec32f6ec5795ba6f0ba0) + "&sign=" + wc7f77547c46e1d23dd20821b58d8165b + "&value=" + str(n1d541db54bc09406bd01a916d8e9f2a0) +""))),"zTfAxXRuP4bwGrtFjByvCai/W+sJI2Yheg9o1LOK7ME6ZV508n3qkcHNUdlDSmQp")),"UTpgwvtbRj43/OxMn+k6qJPIa0FouDSL2EhG79VHmWeNCrBZzXlsKiA8cYydQ5f1")),"fL0cj/6k5WQzust4hagITDmYdEGwFUNKV3Jnxe71XRorS9p2AyHMiBCOb+lZq8vP"))))
    if i8c59691950f4145cd5136e08fdac895a.status_code == 200:
        f4262521c637c5a47dec3373ffc00616b = json.loads(l09aaacf40a230bd1e7cacecf8476a7dd(y0423df98fe0b06646edd0044ba7b7225(k78cab93fdde6f0a901624387aaa1741b(c425684234ce4d5f3b79977925f58a7de(l09aaacf40a230bd1e7cacecf8476a7dd(y0423df98fe0b06646edd0044ba7b7225(i8c59691950f4145cd5136e08fdac895a.text),"uf92c1e9eea0c2de3ab16f59647")),"swbQRVZmWJaBCu2P5vIkpl/36fxE1nHMKFY0gUoAy4zerNdTS97q8cXOiht+GLjD")),"j9022140cb1928a5bde4947675a659197f803"))
        if f4262521c637c5a47dec3373ffc00616b["afa75c7e45077bdcb86ad600b32f4181d"]==34142 and f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["wdecfe87b1632d1c2202d5d4391c9f674"]=="7c6130b4bd2a1448f260449dce787a21":
            if f4262521c637c5a47dec3373ffc00616b["v464a3ff14628b9969c4decf61421596f"]-u40fa45f4a0ccec32f6ec5795ba6f0ba0>30 or f4262521c637c5a47dec3373ffc00616b["v464a3ff14628b9969c4decf61421596f"]-u40fa45f4a0ccec32f6ec5795ba6f0ba0<-30:
                print("设备时间不准")
                progress_bar_error()
            else:
                if f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["hf07a1ff39afa6c"] != za51e1fc6b6a47fe701277cd09ec71299(za51e1fc6b6a47fe701277cd09ec71299(l321cb04d2cbe762b5b8bc83ca0f9ffa3(""+str(f4262521c637c5a47dec3373ffc00616b["v464a3ff14628b9969c4decf61421596f"])+""+str(u40fa45f4a0ccec32f6ec5795ba6f0ba0)+""))) or f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["g1d75b3cd50ab"] != za51e1fc6b6a47fe701277cd09ec71299(l321cb04d2cbe762b5b8bc83ca0f9ffa3(""+str(n1d541db54bc09406bd01a916d8e9f2a0)+""+str(f4262521c637c5a47dec3373ffc00616b["v464a3ff14628b9969c4decf61421596f"])+""+str(f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["x2a3b90b51393c6937931744c85ccfe21"])+""+str(f4262521c637c5a47dec3373ffc00616b["afa75c7e45077bdcb86ad600b32f4181d"])+"")) or f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["ce7cfeaa1535939cfbf"] != za51e1fc6b6a47fe701277cd09ec71299(l321cb04d2cbe762b5b8bc83ca0f9ffa3(""+wc7f77547c46e1d23dd20821b58d8165b+""+str(f4262521c637c5a47dec3373ffc00616b["afa75c7e45077bdcb86ad600b32f4181d"])+""+"i9af372c9fdfc7e9ead0f"+"")) or f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["w559e000095af"] != l321cb04d2cbe762b5b8bc83ca0f9ffa3(za51e1fc6b6a47fe701277cd09ec71299(za51e1fc6b6a47fe701277cd09ec71299(""+str(f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["x2a3b90b51393c6937931744c85ccfe21"])+""+wc7f77547c46e1d23dd20821b58d8165b+""))):
                    print("校验失败")
                    progress_bar_error()
                else:
                    if f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["n9f1d1d61e27e30c2e0af00c35c355df5"] == "single":
                        print("登录成功\n剩余登录次数:" + f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["n18d402c0818313376fc067b66fa46700"])
                    else:
                        print("登录成功\n到期时间:" + datetime.datetime.fromtimestamp(f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"]["f23fb466266ad44627ec0116d1c123d8e"]).strftime('%Y-%m-%d %H:%M:%S'))
                    progress_bar_tech_success()
                    break
        else:
            print(f4262521c637c5a47dec3373ffc00616b["wb5f9fd91c0bce94ac832b95d9fc5ed85"])
            progress_bar_error()
    else:
        print("网络异常")
        progress_bar_error()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import platform
import stat
if platform.system() == "Windows":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    os.system("reg add HKCU\\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1")
GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
PURPLE = '\033[95m'
RESET = '\033[0m'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
def get_rainbow_color(step):
    color_list = ['\033[91m','\033[93m','\033[92m','\033[96m','\033[94m','\033[95m']
    return color_list[step % len(color_list)]
def print_banner_rainbow():
    banner_lines = [
        "┌──────────────────────────────────────────────────────────┐",
        "│                                                          │",
        "│   ████████╗ ██████╗ ██╗   ██╗███████╗    ██████╗ ██╗   ██╗██╗███╗   ███╗ │",
        "│   ╚══██╔══╝██╔═══██╗██║   ██║██╔════╝    ██╔══██╗██║   ██║██║████╗ ████║ │",
        "│      ██║   ██║   ██║██║   ██║█████╗      ██████╔╝██║   ██║██║██╔████╔██║ │",
        "│      ██║   ██║   ██║██║   ██║██╔══╝      ██╔══██╗██║   ██║██║██║╚██╔╝██║ │",
        "│      ██║   ╚██████╔╝╚██████╔╝███████╗    ██║  ██║╚██████╔╝██║██║ ╚═╝ ██║ │",
        "│      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝     ╚═╝ │",
        "│                                                          │",
        "│                 ★ 天赐工具箱 ★                             │",
        "└──────────────────────────────────────────────────────────┘"
    ]
    for idx, line in enumerate(banner_lines):
        c = get_rainbow_color(idx)
        print(f"{c}{line}{RESET}")
def print_normal_banner(theme_color):
    banner = f"""{theme_color}
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   ████████╗ ██████╗ ██╗   ██╗███████╗    ██████╗ ██╗   ██╗██╗███╗   ███╗ │
│   ╚══██╔══╝██╔═══██╗██║   ██║██╔════╝    ██╔══██╗██║   ██║██║████╗ ████║ │
│      ██║   ██║   ██║██║   ██║█████╗      ██████╔╝██║   ██║██║██╔████╔██║ │
│      ██║   ██║   ██║██║   ██║██╔══╝      ██╔══██╗██║   ██║██║██║╚██╔╝██║ │
│      ██║   ╚██████╔╝╚██████╔╝███████╗    ██║  ██║╚██████╔╝██║██║ ╚═╝ ██║ │
│      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝     ╚═╝ │
│                                                          │
│                 ★ 天赐工具箱 ★                             │
└──────────────────────────────────────────────────────────┘{RESET}"""
    print(banner)
# ==========第一页炫彩菜单【全部编号两位对齐】==========
def show_menu_rainbow_page1():
    menu_text = """
┌──────────────────────────────────────────────┐
│              美化菜单                         │
├──────────────────────────────────────────────┤
│ 01. 全自动载具                               │
│ 02. 全自动伪实体                             │
│ 03. 全自动地铁枪皮                           │
│ 04. 全自动古墓美化                           │
│ 05. 全自动局内贴图                           │
│ 06. 自动查找pak                              │
│ 07. 全自动载具入场                           │
│ 08. 全自动天线美化                           │
│ 09. 全自动仓库入场                           │
│ 10. 全自动写升级枪                           │
│ 11. 全自动水印修改                           │
│ 12. 全自动语音动作                           │
│ 13. 全自动品质修改                           │
│ 14. 自动写配置                               │
│ 15. 自动头像框美化                           │
│ 16. 全自动播报美化                           │
│ 17. 全自动品质修改                           │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│              其他菜单                         │
├──────────────────────────────────────────────┤
│ 18. 删注释                                   │
│ 19. 修复美化配置                             │
│ 20. 免root输出                               │
│ 21. 经典转伪实体                             │
│ 22. 经典转古墓                               │
│ 23. 检查配置                                 │
│ 24. 加注释                                   │
│ 25. txt转py                                  │
│ 26. py转配料表                               │
│ 27. py转txt                                  │
│ 28. 全自动地铁金光                           │
│ 29. 全自动大厅完美                           │
│ 30. 全自动大厅手持                           │
│ 31. 全自动大厅动作                           │
│ 32. 全自动大厅背景                           │
│ 33. 地铁零战备修改                           │
│ 34. 全自动修改加载动画                       │
│ 00. 退出程序                                 │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│              偷配置菜单                       │
├──────────────────────────────────────────────┤
│ 35. 偷载具入场                               │
│ 36. 偷语音动作                               │
│ 37. 偷伪实体配置                             │
│ 38. 偷头像框配置                             │
│ 39. 偷人物入场                               │
│ 40. 偷经典配置                               │
│ 41. 偷古墓配置                               │
│ 42. 偷动作配置                               │
│ 43. 偷地铁配置                               │
│ 44. 偷称号配置                               │
│ 45. 偷播报配置                               │
│ 46. 偷背景配置                               │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│            打包功能菜单                       │
├──────────────────────────────────────────────┤
│ 47. UE4解包                                  │
│ 48. UE4打包                                  │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│           拓展其他菜单                       │
├──────────────────────────────────────────────┤
│ 49. ai对话                                   │
│ 50. 创建快捷指令                              │
│ 51. ai对话2                                   │
│ 01. 选择颜色                                 │
│ 54. 切换到第二页                             │
└──────────────────────────────────────────────┘
"""
    lines = menu_text.splitlines()
    for index, line in enumerate(lines):
        color = get_rainbow_color(index)
        print(f"{color}{line}{RESET}")

# ==========第二页炫彩菜单【全新编号，不和第一页重复】==========
def show_menu_rainbow_page2():
    menu_text = """
┌──────────────────────────────────────────────┐
│                第二页拓展菜单                 │
├──────────────────────────────────────────────┤
│ 101. 批量py合并                              │
│ 102. 批量py拆分                              │
│ 103. 配置有效性批量校验                       │
│ 104. 批量去除重复条目                         │
│ 105. 批量添加自定义注释                       │
│ 106. pak批量备份脚本                         │
│ 107. uasset批量重命名工具                     │
│ 108. uexp文件编码修复                        │
│ 109. 配置压缩导出                            │
│ 110. 配置解压导入                            │
│ 111. 打印全部目录文件列表                    │
│ 112. 清理临时缓存文件                        │
│ 113. 查看磁盘占用大小                        │
│ 114. 批量转换换行格式                         │
│ 115. 配置去空行工具                          │
│ 53. 返回第一页                               │
│ 00. 退出程序                                 │
└──────────────────────────────────────────────┘
"""
    lines = menu_text.splitlines()
    for index, line in enumerate(lines):
        color = get_rainbow_color(index)
        print(f"{color}{line}{RESET}")

# ==========单色主题 第一页==========
def show_menu_normal_page1(theme_color):
    menu = f"""{theme_color}
┌──────────────────────────────────────────────┐
│              美化菜单                         │
├──────────────────────────────────────────────┤
│ 01. 全自动载具                               │
│ 02. 全自动伪实体                             │
│ 03. 全自动地铁枪皮                           │
│ 04. 全自动古墓美化                           │
│ 05. 全自动局内贴图                           │
│ 06. 自动查找pak                              │
│ 07. 全自动载具入场                           │
│ 08. 全自动天线美化                           │
│ 09. 全自动仓库入场                           │
│ 10. 全自动写升级枪                           │
│ 11. 全自动水印修改                           │
│ 12. 全自动语音动作                           │
│ 13. 全自动品质修改                           │
│ 14. 自动写配置                               │
│ 15. 自动头像框美化                           │
│ 16. 全自动播报美化                           │
│ 17. 全自动品质修改                           │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│              其他菜单                         │
├──────────────────────────────────────────────┤
│ 18. 删注释                                   │
│ 19. 修复美化配置                             │
│ 20. 免root输出                               │
│ 21. 经典转伪实体                             │
│ 22. 经典转古墓                               │
│ 23. 检查配置                                 │
│ 24. 加注释                                   │
│ 25. txt转py                                  │
│ 26. py转配料表                               │
│ 27. py转txt                                  │
│ 28. 全自动地铁金光                           │
│ 29. 全自动大厅完美                           │
│ 30. 全自动大厅手持                           │
│ 31. 全自动大厅动作                           │
│ 32. 全自动大厅背景                           │
│ 33. 地铁零战备修改                           │
│ 34. 全自动修改加载动画                       │
│ 00. 退出程序                                 │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│              偷配置菜单                       │
├──────────────────────────────────────────────┤
│ 35. 偷载具入场                               │
│ 36. 偷语音动作                               │
│ 37. 偷伪实体配置                             │
│ 38. 偷头像框配置                             │
│ 39. 偷人物入场                               │
│ 40. 偷经典配置                               │
│ 41. 偷古墓配置                               │
│ 42. 偷动作配置                               │
│ 43. 偷地铁配置                               │
│ 44. 偷称号配置                               │
│ 45. 偷播报配置                               │
│ 46. 偷背景配置                               │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│            打包功能菜单                       │
├──────────────────────────────────────────────┤
│ 47. UE4解包                                  │
│ 48. UE4打包                                  │
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│           拓展其他菜单                       │
├──────────────────────────────────────────────┤
│ 49. ai对话                                   │
│ 50. 创建快捷指令                              │
│ 51. ai对话2                                   │
│ 01. 选择颜色                                 │
│ 54. 切换到第二页                             │
└──────────────────────────────────────────────┘{RESET}
"""
    print(menu)

# ==========单色主题 第二页==========
def show_menu_normal_page2(theme_color):
    menu = f"""{theme_color}
┌──────────────────────────────────────────────┐
│                第二页拓展菜单                 │
├──────────────────────────────────────────────┤
│ 101. 批量py合并                              │
│ 102. 批量py拆分                              │
│ 103. 配置有效性批量校验                       │
│ 104. 批量去除重复条目                         │
│ 105. 批量添加自定义注释                       │
│ 106. pak批量备份脚本                         │
│ 107. uasset批量重命名工具                     │
│ 108. uexp文件编码修复                        │
│ 109. 配置压缩导出                            │
│ 110. 配置解压导入                            │
│ 111. 打印全部目录文件列表                    │
│ 112. 清理临时缓存文件                        │
│ 113. 查看磁盘占用大小                        │
│ 114. 批量转换换行格式                         │
│ 115. 配置去空行工具                          │
│ 53. 返回第一页                               │
│ 00. 退出程序                                 │
└──────────────────────────────────────────────┘{RESET}
"""
    print(menu)

def add_executable_permission(filepath, msg_color):
    if os.path.exists(filepath):
        try:
            current_permissions = os.stat(filepath).st_mode
            os.chmod(filepath, current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print(f"{msg_color}[✓] 已添加执行权限: {filepath}{RESET}")
            return True
        except Exception as e:
            print(f"{msg_color}[✗] 添加权限失败: {e}{RESET}")
            return False
    return False

def get_function_filename(choice):
    """第一页编号映射"""
    function_map_page1 = {
        '1': '全自动载具',
        '2': '全自动伪实体',
        '3': '全自动地铁枪皮',
        '4': '全自动古墓美化',
        '5': '全自动局内贴图',
        '6': '自动查找pak',
        '7': '全自动载具入场',
        '8': '全自动天线美化',
        '9': '全自动仓库入场',
        '10': '全自动写升级枪',
        '11': '全自动水印修改',
        '12': '全自动语音动作',
        '13': '全自动品质修改',
        '14': '自动写配置',
        '15': '自动头像框美化',
        '16': '全自动播报美化',
        '17': '全自动品质修改',
        '18': '删注释',
        '19': '修复美化配置',
        '20': '免root输出',
        '21': '经典转伪实体',
        '22': '经典转古墓',
        '23': '检查配置',
        '24': '加注释',
        '25': 'txt转py',
        '26': 'py转配料表',
        '27': 'py转txt',
        '28': '全自动地铁金光',
        '29': '全自动大厅完美',
        '30': '全自动大厅手持',
        '31': '全自动大厅动作',
        '32': '全自动大厅背景',
        '33': '地铁零战备修改',
        '34': '全自动修改加载动画',
        '35': '偷载具入场',
        '36': '偷语音动作',
        '37': '偷伪实体配置',
        '38': '偷头像框配置',
        '39': '偷人物入场',
        '40': '偷经典配置',
        '41': '偷古墓配置',
        '42': '偷动作配置',
        '43': '偷地铁配置',
        '44': '偷称号配置',
        '45': '偷播报配置',
        '46': '偷背景配置',
        '47': 'UE4解包',
        '48': 'UE4打包',
        '49': 'ai对话1',
        '50': '创建快捷指令',
        '51': 'ai对话2',
    }
    """第二页全新编号映射，不和第一页冲突"""
    function_map_page2 = {
        '101': '批量py合并',
        '102': '批量py拆分',
        '103': '配置有效性批量校验',
        '104': '批量去除重复条目',
        '105': '批量添加自定义注释',
        '106': 'pak批量备份脚本',
        '107': 'uasset批量重命名工具',
        '108': 'uexp文件编码修复',
        '109': '配置压缩导出',
        '110': '配置解压导入',
        '111': '打印全部目录文件列表',
        '112': '清理临时缓存文件',
        '113': '查看磁盘占用大小',
        '114': '批量转换换行格式',
        '115': '配置去空行工具',
    }
    if choice in function_map_page1:
        return function_map_page1[choice]
    if choice in function_map_page2:
        return function_map_page2[choice]
    return None

def execute_function(filename, msg_color):
    if not filename:
        print(f"{msg_color}[!] 无效的功能选择{RESET}")
        return False
    filepath = os.path.join(SCRIPT_DIR, filename)
    if not os.path.exists(filepath):
        print(f"{msg_color}[!] 功能文件不存在: {filename}{RESET}")
        print(f"{msg_color}[!] 请确保同目录下存在该可执行文件{RESET}")
        print(f"{msg_color}[i] 当前目录文件:{RESET}")
        try:
            for f in os.listdir(SCRIPT_DIR):
                if os.path.isfile(os.path.join(SCRIPT_DIR, f)):
                    print(f"{msg_color}    - {f}{RESET}")
        except Exception:
            pass
        return False
    add_executable_permission(filepath, msg_color)
    try:
        print(f"{msg_color}[→] 正在启动: {filename}{RESET}")
        print(f"{msg_color}────────────────────────────────────────{RESET}")
        if platform.system() == "Windows":
            if filepath.lower().endswith(".py"):
                subprocess.run([sys.executable, filepath], cwd=SCRIPT_DIR)
            else:
                subprocess.run(filepath, cwd=SCRIPT_DIR)
        else:
            subprocess.run([filepath], cwd=SCRIPT_DIR)
        print(f"{msg_color}────────────────────────────────────────{RESET}")
        print(f"{msg_color}[✓] 功能执行完成{RESET}")
        return True
    except Exception as e:
        print(f"{msg_color}[✗] 执行失败: {e}{RESET}")
        return False

def safe_input(prompt):
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return ''

theme_color = YELLOW
is_rainbow = True
current_page = 1

def main():
    global theme_color, is_rainbow, current_page
    while True:
        try:
            os.system('clear' if platform.system() != "Windows" else 'cls')
        except Exception:
            pass
        if is_rainbow:
            print_banner_rainbow()
            if current_page == 1:
                show_menu_rainbow_page1()
            elif current_page == 2:
                show_menu_rainbow_page2()
            prompt_color = get_rainbow_color(7)
        else:
            print_normal_banner(theme_color)
            if current_page == 1:
                show_menu_normal_page1(theme_color)
            elif current_page == 2:
                show_menu_normal_page2(theme_color)
            prompt_color = theme_color
        choice = safe_input(f"{prompt_color}请选择功能 (输入编号): {RESET}")
        if choice in ('0','00'):
            print(f"{prompt_color}感谢使用，再见！{RESET}")
            break
        #54 切换第二页
        if choice == "54":
            current_page = 2
            continue
        #53 返回第一页
        if choice == "53":
            current_page = 1
            continue
        if choice == "01":
            print(f"\n{RESET}----------选择主题颜色----------")
            print("0 = 炫彩彩虹(默认，整个界面全部炫彩)")
            print("1 = 绿色")
            print("2 = 蓝色")
            print("3 = 黄色")
            print("4 = 红色")
            print("5 = 紫色")
            col_opt = safe_input("请输入颜色序号：")
            if col_opt == "0":
                is_rainbow = True
                print(f"{RESET}[✓] 已切换为【炫彩彩虹】主题，下一页生效")
            elif col_opt == "1":
                is_rainbow = False
                theme_color = GREEN
                print(f"{GREEN}[✓] 已切换为绿色主题{RESET}")
            elif col_opt == "2":
                is_rainbow = False
                theme_color = BLUE
                print(f"{BLUE}[✓] 已切换为蓝色主题{RESET}")
            elif col_opt == "3":
                is_rainbow = False
                theme_color = YELLOW
                print(f"{YELLOW}[✓] 已切换为黄色主题{RESET}")
            elif col_opt == "4":
                is_rainbow = False
                theme_color = RED
                print(f"{RED}[✓] 已切换为红色主题{RESET}")
            elif col_opt == "5":
                is_rainbow = False
                theme_color = PURPLE
                print(f"{PURPLE}[✓] 已切换为紫色主题{RESET}")
            else:
                print(f"{RED}[!] 无效序号，颜色未变动{RESET}")
            safe_input(f"\n{prompt_color}按回车键返回主菜单...{RESET}")
            continue

        filename = get_function_filename(choice)
        msg_c = get_rainbow_color(5) if is_rainbow else theme_color
        if filename:
            execute_function(filename, msg_c)
        else:
            print(f"{msg_c}[!] 该编号暂未绑定功能文件，或输入无效{RESET}")
        safe_input(f"\n{msg_c}按回车键继续...{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RESET}程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[✗] 顶层程序异常: {e}{RESET}")
        safe_input("回车退出...")
        sys.exit(1)

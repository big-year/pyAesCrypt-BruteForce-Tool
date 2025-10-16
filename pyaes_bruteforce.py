#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pyAesCrypt BruteForce Tool v1.1 (multiprocess optimized)
改动点：
- 使用 multiprocessing.Pool + imap_unordered 代替 ThreadPoolExecutor
- 流式产生密码（不把全部密码一次塞内存）
- 每个进程使用固定临时文件（避免频繁创建大量临时文件）
- 进度打印降频、批量调度(chunksize)降低调度开销
- 掩码生成器改为逐个字符串输出（流式）
"""

import os
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed  # 仍保留以防扩展
import itertools
import string
import subprocess
from pathlib import Path
import tempfile

try:
    import pyAesCrypt
except ImportError:
    print("[!] pyAesCrypt 未安装. 正在自动安装...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyAesCrypt"])
    import pyAesCrypt

# ---------------- 颜色与统计类（保留并略微调整） ----------------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Stats:
    def __init__(self):
        self.start_time = time.time()
        self.attempts = 0
        self.found = False
        self.password = None
        self.lock = threading.Lock()
    def increment(self, n=1):
        with self.lock:
            self.attempts += n
    def set_found(self, password):
        with self.lock:
            self.found = True
            self.password = password
    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0
            return {
                'attempts': self.attempts,
                'elapsed': elapsed,
                'rate': rate,
                'found': self.found,
                'password': self.password
            }

# ---------------- 全局（用于子进程） ----------------
GLOBAL_TARGET_FILE = None
GLOBAL_BUFFER_SIZE = 64 * 1024
GLOBAL_TMP_DIR = None

def mp_init(target_file, tmp_dir, buffer_size):
    """Pool initializer: 在子进程中设置全局变量"""
    global GLOBAL_TARGET_FILE, GLOBAL_BUFFER_SIZE, GLOBAL_TMP_DIR
    GLOBAL_TARGET_FILE = target_file
    GLOBAL_BUFFER_SIZE = buffer_size
    GLOBAL_TMP_DIR = tmp_dir

def _mp_test_password(password):
    """
    在子进程中执行：尝试使用 password 解密到每个进程固定的临时文件。
    成功返回 password，失败返回 None。
    """
    import os
    try:
        pid = os.getpid()
        tmp_out = os.path.join(GLOBAL_TMP_DIR, f"pyaes_tmp_{pid}.bin")
        # pyAesCrypt.decryptFile 会抛异常表示失败
        pyAesCrypt.decryptFile(GLOBAL_TARGET_FILE, tmp_out, password, GLOBAL_BUFFER_SIZE)
        # 若成功，删除临时文件并返回密码
        if os.path.exists(tmp_out):
            try:
                os.remove(tmp_out)
            except:
                pass
        return password
    except Exception:
        # 确保清理
        try:
            pid = os.getpid()
            tmp_out = os.path.join(GLOBAL_TMP_DIR, f"pyaes_tmp_{pid}.bin")
            if os.path.exists(tmp_out):
                os.remove(tmp_out)
        except:
            pass
        return None

# ---------------- 主类 ----------------
class PyAesBruteForcer:
    def __init__(self, target_file, output_file=None, threads=4, verbose=False):
        self.target_file = target_file
        self.output_file = output_file or "decrypted_output.txt"
        self.threads = threads
        self.verbose = verbose
        self.stats = Stats()
        self.stop_event = threading.Event()
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"目标文件不存在: {target_file}")

    # --- 原 test_password 可保留但在多进程路径不使用 ---
    def test_password(self, password):
        if self.stop_event.is_set():
            return False
        try:
            temp_output = f"{self.output_file}.tmp.{threading.get_ident()}"
            pyAesCrypt.decryptFile(self.target_file, temp_output, password, GLOBAL_BUFFER_SIZE)
            if os.path.exists(temp_output):
                os.remove(temp_output)
            return True
        except Exception:
            return False
        finally:
            self.stats.increment()

    # --- 字典攻击（保持接口，但流式传入） ---
    def dictionary_attack(self, wordlist_file):
        print(f"{Colors.CYAN}[*] 启动字典攻击模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 字典文件: {wordlist_file}{Colors.END}")
        print(f"{Colors.BLUE}[*] 进程数: {self.threads}{Colors.END}")
        print()
        if not os.path.exists(wordlist_file):
            print(f"{Colors.RED}[!] 字典文件不存在: {wordlist_file}{Colors.END}")
            return False
        def gen():
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd:
                        yield pwd
        return self._run_attack_multiprocess(gen())

    # --- 暴力破解（流式生成器） ---
    def brute_force_attack(self, charset, min_length=1, max_length=8):
        print(f"{Colors.CYAN}[*] 启动暴力破解模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 字符集: {charset[:50]}{'...' if len(charset) > 50 else ''}{Colors.END}")
        print(f"{Colors.BLUE}[*] 密码长度: {min_length}-{max_length}{Colors.END}")
        print(f"{Colors.BLUE}[*] 进程数: {self.threads}{Colors.END}")
        print()
        def gen():
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(charset, repeat=length):
                    yield ''.join(combo)
        return self._run_attack_multiprocess(gen())

    # --- 掩码攻击（改为逐个字符串产出） ---
    def mask_attack(self, mask):
        print(f"{Colors.CYAN}[*] 启动掩码攻击模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 掩码: {mask}{Colors.END}")
        print(f"{Colors.BLUE}[*] 进程数: {self.threads}{Colors.END}")
        print()
        return self._run_attack_multiprocess(self._generate_mask_passwords_stream(mask))

    def _generate_mask_passwords_stream(self, mask):
        """掩码 -> 逐个字符串流式生成"""
        charset_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.ascii_letters + string.digits + string.punctuation
        }
        positions = []
        i = 0
        while i < len(mask):
            if mask[i:i+2] in charset_map:
                positions.append(charset_map[mask[i:i+2]])
                i += 2
            else:
                positions.append([mask[i]])
                i += 1
        for combo in itertools.product(*positions):
            yield ''.join(combo)

    # ---------------- 多进程运行核心 ----------------
    def _run_attack_multiprocess(self, passwords_iterable):
        """
        使用 multiprocessing.Pool + imap_unordered 流式消费 passwords_iterable（可迭代）。
        chunksize 控制一次提交的批量大小，较大值减少调度开销但增加延迟响应找到密码时的终止延迟。
        """
        import multiprocessing as mp
        from itertools import islice

        tmp_dir = tempfile.gettempdir()
        buffer_size = 64 * 1024

        cpu_cnt = mp.cpu_count()
        workers = min(self.threads or cpu_cnt, cpu_cnt)
        print(f"{Colors.BLUE}[*] 使用多进程: {workers} 个进程 (CPU 核心 {cpu_cnt}){Colors.END}")

        manager = mp.Manager()
        found_flag = manager.Event()
        attempts_val = manager.Value('L', 0)  # unsigned long
        lock = manager.Lock()

        # 进度打印线程（主进程）
        def _progress_printer():
            last = 0
            while not found_flag.is_set() and not self.stop_event.is_set():
                with lock:
                    attempts = attempts_val.value
                elapsed = time.time() - self.stats.start_time
                rate = (attempts - last) / 1.0 if elapsed > 0 else 0
                # 同步 stats（大致值）
                self.stats.attempts = attempts
                elapsed_str = time.strftime('%H:%M:%S', time.gmtime(elapsed))
                print(f"\r{Colors.CYAN}[*] 尝试: {attempts:,} | 速度(avg): {self.stats.get_stats()['rate']:.0f}/s | 时间: {elapsed_str}{Colors.END}", end='', flush=True)
                last = attempts
                time.sleep(1)
        prog_thread = threading.Thread(target=_progress_printer)
        prog_thread.daemon = True
        prog_thread.start()

        # Pool 初始化器传入全局参数，保证 Windows spawn 模式也可用
        pool = mp.Pool(processes=workers, initializer=mp_init, initargs=(self.target_file, tmp_dir, buffer_size))
        chunksize = 256  # 可调。若你的密码生成非常密集，可试 512/1024；若希望快速响应找到密码则减小

        try:
            imap = pool.imap_unordered(_mp_test_password, passwords_iterable, chunksize)
            for result in imap:
                with lock:
                    attempts_val.value += 1
                    # keep class stats roughly in sync
                    self.stats.attempts = attempts_val.value

                if result:
                    # 找到密码
                    found_flag.set()
                    self.stats.set_found(result)
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] 密码找到: {result}{Colors.END}")
                    # 主进程负责最终解密到目标文件
                    try:
                        pyAesCrypt.decryptFile(self.target_file, self.output_file, result, buffer_size)
                        print(f"{Colors.GREEN}[+] 文件已解密到: {self.output_file}{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.RED}[!] 最终解密失败: {e}{Colors.END}")
                    pool.terminate()
                    pool.join()
                    return True

                if self.stop_event.is_set():
                    break

            # 遍历结束未找到
            pool.close()
            pool.join()
            print(f"\n{Colors.RED}[-] 未找到正确密码{Colors.END}")
            return False

        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            raise
        finally:
            try:
                pool.terminate()
            except:
                pass

# ---------------- 其他小工具 ----------------
def create_sample_wordlist():
    wordlist = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "111111",
        "123123", "admin", "letmein", "welcome", "monkey",
        "dragon", "master", "hello", "freedom", "whatever",
        "qwertyuiop", "trustno1", "jordan23", "princess",
        "password123", "welcome123", "admin123", "root", "toor",
        "pass", "test", "guest", "user", "demo", "sample"
    ]
    with open("common_passwords.txt", "w") as f:
        for pwd in wordlist:
            f.write(pwd + "\n")
    print(f"{Colors.GREEN}[+] 示例字典文件已创建: common_passwords.txt{Colors.END}")

def print_banner():
    banner = rf"""{Colors.CYAN}{Colors.BOLD}
 ____        _            ____             _       
|  _ \ _   _| |_ ___  ___| __ ) _ __ _   _| |_ ___ 
| |_) | | | | __/ _ \/ __|  _ \| '__| | | | __/ _ \\
|  __/| |_| | ||  __/\__ \ |_) | |  | |_| | ||  __/
|_|    \__, |\__\___||___/____/|_|   \__,_|\__\___|
       |___/                                      
                                                  
    pyAesCrypt 高效暴力破解工具 v1.1 (multiprocess)
    
{Colors.END}{Colors.YELLOW}    [*] 支持字典攻击、暴力破解、掩码攻击
    [*] 多进程并发处理，高效快速
{Colors.END}
"""
    print(banner)

# ---------------- CLI 主程序 ----------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="pyAesCrypt 高效暴力破解工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""使用示例:
  字典攻击:
    python pyaes_bruteforce.py -f encrypted.aes -w wordlist.txt
    
  暴力破解:
    python pyaes_bruteforce.py -f encrypted.aes -b -c "0123456789" -l 4-6 -t 8
    
  掩码攻击:
    python pyaes_bruteforce.py -f encrypted.aes -m "?d?d?d?d"  # 4位数字
"""
    )
    parser.add_argument("-f", "--file", help="目标加密文件")
    parser.add_argument("-o", "--output", default="decrypted.txt", help="解密后输出文件 (默认: decrypted.txt)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="并发进程数 (默认: 4)")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-w", "--wordlist", help="字典文件路径")
    group.add_argument("-b", "--brute", action="store_true", help="暴力破解模式")
    group.add_argument("-m", "--mask", help="掩码攻击模式")
    group.add_argument("--create-word

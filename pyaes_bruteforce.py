#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pyAesCrypt BruteForce Tool v2.1 (multiprocess, 支持 --tmp 参数)
说明：
- 使用 multiprocessing.Pool 提升并行效率（避开 GIL）
- 密码流式生成（不一次性载入大量内存）
- 每进程使用固定临时文件写入到 --tmp 指定目录（建议指向 tmpfs 如 /dev/shm）
- 支持字典(-w)、暴力(-b)、掩码(-m) 模式
"""

import os
import sys
import time
import argparse
import threading
import itertools
import string
import subprocess
import tempfile
import multiprocessing as mp

try:
    import pyAesCrypt
except ImportError:
    print("[!] pyAesCrypt 未安装. 正在自动安装...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyAesCrypt"])
    import pyAesCrypt

# ---------------- Colors ----------------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ---------------- Global for worker ----------------
GLOBAL_TARGET_FILE = None
GLOBAL_BUFFER_SIZE = 64 * 1024
GLOBAL_TMPDIR = None

def _mp_worker_try(password):
    """
    子进程尝试：把解密输出写入 GLOBAL_TMPDIR/pyaes_tmp_<pid>.bin
    成功返回 password，否则返回 None
    """
    import os
    try:
        pid = os.getpid()
        tmp_out = os.path.join(GLOBAL_TMPDIR, f"pyaes_tmp_{pid}.bin")
        # pyAesCrypt.decryptFile 若密码错误会抛异常
        pyAesCrypt.decryptFile(GLOBAL_TARGET_FILE, tmp_out, password, GLOBAL_BUFFER_SIZE)
        # 成功 -> 清理并返回密码
        if os.path.exists(tmp_out):
            try:
                os.remove(tmp_out)
            except Exception:
                pass
        return password
    except Exception:
        # 失败或异常 -> 尝试清理再返回 None
        try:
            if 'tmp_out' in locals() and os.path.exists(tmp_out):
                os.remove(tmp_out)
        except Exception:
            pass
        return None

# ---------------- Stats ----------------
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
    def set_found(self, pwd):
        with self.lock:
            self.found = True
            self.password = pwd
    def snapshot(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0
            return {'attempts': self.attempts, 'elapsed': elapsed, 'rate': rate, 'found': self.found, 'password': self.password}

# ---------------- Brute Forcer ----------------
class PyAesBruteForcer:
    def __init__(self, target_file, output_file=None, processes=None, verbose=False, tmpdir=None):
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"目标文件不存在: {target_file}")
        self.target_file = target_file
        self.output_file = output_file or "decrypted_output.txt"
        self.processes = processes or mp.cpu_count()
        self.verbose = verbose
        self.stats = Stats()
        self.stop_flag = mp.Value('b', False)  # 主进程用于通知停止（也可用 Event）
        # tmpdir 验证/设置
        if tmpdir:
            if not os.path.isdir(tmpdir):
                raise FileNotFoundError(f"指定的 tmp 目录不存在: {tmpdir}")
            if not os.access(tmpdir, os.W_OK):
                raise PermissionError(f"指定的 tmp 目录不可写: {tmpdir}")
            self.tmpdir = tmpdir
        else:
            self.tmpdir = tempfile.gettempdir()

    # ---------- Generators ----------
    def _dict_generator(self, wordlist_file):
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                pwd = line.strip()
                if pwd:
                    yield pwd

    def _brute_generator(self, charset, min_len, max_len):
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield ''.join(combo)

    def _mask_generator(self, mask):
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
            token2 = mask[i:i+2]
            if token2 in charset_map:
                positions.append(charset_map[token2])
                i += 2
            else:
                positions.append(mask[i])
                i += 1
        for combo in itertools.product(*positions):
            yield ''.join(combo)

    # ---------- Core: multiprocess runner ----------
    def _run_attack_multiprocess(self, password_iterable, chunksize=256):
        """
        password_iterable: generator of passwords (streaming)
        chunksize: 调整调度/吞吐的折中，增大会降低调度开销但找到密码后的响应延迟增加
        """
        global GLOBAL_TARGET_FILE, GLOBAL_TMPDIR
        GLOBAL_TARGET_FILE = self.target_file
        GLOBAL_TMPDIR = self.tmpdir

        workers = max(1, min(self.processes, mp.cpu_count()))
        print(f"{Colors.BLUE}[*] 使用进程数: {workers}，临时目录: {self.tmpdir}{Colors.END}")

        pool = mp.Pool(processes=workers)
        try:
            # imap_unordered 需要可重复迭代对象；我们步进从 generator 手动以 chunksize 提交会更稳健
            # 这里我们直接用 pool.imap_unordered，因为 Python 会自己处理 chunksize
            imap = pool.imap_unordered(_mp_worker_try, password_iterable, chunksize)

            # 启动进度打印线程（在主进程）
            stop_print = threading.Event()
            def _progress():
                while not stop_print.is_set():
                    s = self.stats.snapshot()
                    if s['found']:
                        break
                    elapsed_str = time.strftime('%H:%M:%S', time.gmtime(s['elapsed']))
                    print(f"\r{Colors.CYAN}[*] 尝试: {s['attempts']:,} | 速度: {s['rate']:.0f}/s | 时间: {elapsed_str}{Colors.END}", end='', flush=True)
                    time.sleep(1)
            t = threading.Thread(target=_progress)
            t.daemon = True
            t.start()

            for res in imap:
                # 每收到一个结果就认为完成一个尝试（res None 或 password）
                self.stats.increment(1)

                if res:
                    # 找到密码
                    self.stats.set_found(res)
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] 密码找到: {res}{Colors.END}")
                    # 主进程负责最终解密到目标输出文件
                    pyAesCrypt.decryptFile(self.target_file, self.output_file, res, GLOBAL_BUFFER_SIZE)
                    stop_print.set()
                    pool.terminate()
                    pool.join()
                    return True

                # 检查是否应当停止（用户中断等）
                if self.stop_flag.value:
                    stop_print.set()
                    pool.terminate()
                    pool.join()
                    return False

            # 遍历结束未找到
            stop_print.set()
            pool.close()
            pool.join()
            print(f"\n{Colors.RED}[-] 未找到正确密码{Colors.END}")
            return False

        except KeyboardInterrupt:
            print("\n" + Colors.YELLOW + "[*] 用户中断，正在终止进程池..." + Colors.END)
            self.stop_flag.value = True
            pool.terminate()
            pool.join()
            raise
        except Exception as e:
            try:
                pool.terminate()
                pool.join()
            except Exception:
                pass
            raise e

    # ---------- Public attacks ----------
    def dictionary_attack(self, wordlist_file):
        print(f"{Colors.CYAN}[*] 启动字典攻击模式{Colors.END}")
        if not os.path.exists(wordlist_file):
            print(f"{Colors.RED}[!] 字典文件不存在: {wordlist_file}{Colors.END}")
            return False
        gen = self._dict_generator(wordlist_file)
        return self._run_attack_multiprocess(gen)

    def brute_force_attack(self, charset, min_length=1, max_length=4):
        print(f"{Colors.CYAN}[*] 启动暴力破解模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 字符集: {charset}{Colors.END}")
        print(f"{Colors.BLUE}[*] 密码长度: {min_length}-{max_length}{Colors.END}")
        gen = self._brute_generator(charset, min_length, max_length)
        return self._run_attack_multiprocess(gen)

    def mask_attack(self, mask):
        print(f"{Colors.CYAN}[*] 启动掩码攻击模式{Colors.END}")
        gen = self._mask_generator(mask)
        return self._run_attack_multiprocess(gen)

# ---------------- Helpers ----------------
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
                                                   
    pyAesCrypt 高效暴力破解工具 v2.1
    
{Colors.END}{Colors.YELLOW}    [*] 支持字典攻击、暴力破解、掩码攻击
    [*] 多进程并发，支持 --tmp 指定临时目录（推荐 tmpfs）
{Colors.END}
"""
    print(banner)

# ---------------- Main ----------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="pyAesCrypt 高效暴力破解工具 v2.1")
    parser.add_argument("-f", "--file", help="目标加密文件")
    parser.add_argument("-o", "--output", default="decrypted.txt", help="解密后输出文件 (默认: decrypted.txt)")
    parser.add_argument("-p", "--processes", type=int, default=None, help="进程数 (默认: CPU 核心数)")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--tmp", dest="tmpdir", help="临时目录，用于写入进程临时文件（建议指向 tmpfs，如 /dev/shm）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-w", "--wordlist", help="字典文件路径")
    group.add_argument("-b", "--brute", action="store_true", help="暴力破解模式")
    group.add_argument("-m", "--mask", help="掩码攻击模式")
    group.add_argument("--create-wordlist", action="store_true", help="创建示例字典文件")
    parser.add_argument("-c", "--charset", default="0123456789", help="暴力破解字符集 (默认: 数字)")
    parser.add_argument("-l", "--length", default="1-4", help="密码长度范围 (格式: min-max, 默认: 1-4)")

    args = parser.parse_args()

    if args.create_wordlist:
        create_sample_wordlist()
        return

    if not args.file:
        parser.error("参数 -f/--file 是必需的（除非使用 --create-wordlist）")

    # 验证 tmpdir（如果传了）
    tmpdir = args.tmpdir
    if tmpdir:
        tmpdir = os.path.abspath(tmpdir)
        if not os.path.isdir(tmpdir):
            print(f"{Colors.RED}[!] 指定的 tmp 目录不存在: {tmpdir}{Colors.END}")
            sys.exit(1)
        if not os.access(tmpdir, os.W_OK):
            print(f"{Colors.RED}[!] 指定的 tmp 目录不可写: {tmpdir}{Colors.END}")
            sys.exit(1)
    else:
        tmpdir = tempfile.gettempdir()

    try:
        bruteforcer = PyAesBruteForcer(
            target_file=args.file,
            output_file=args.output,
            processes=args.processes,
            verbose=args.verbose,
            tmpdir=tmpdir
        )

        success = False
        start_time = time.time()

        if args.wordlist:
            success = bruteforcer.dictionary_attack(args.wordlist)
        elif args.brute:
            min_len, max_len = map(int, args.length.split('-'))
            success = bruteforcer.brute_force_attack(args.charset, min_len, max_len)
        elif args.mask:
            success = bruteforcer.mask_attack(args.mask)

        elapsed = time.time() - start_time
        stats = bruteforcer.stats.snapshot()

        print(f"\n{Colors.CYAN}=== 攻击完成 ==={Colors.END}")
        print(f"{Colors.BLUE}总尝试次数: {stats['attempts']:,}{Colors.END}")
        print(f"{Colors.BLUE}总耗时: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}{Colors.END}")
        print(f"{Colors.BLUE}平均速度: {stats['rate']:.0f} 密码/秒{Colors.END}")

        if success:
            print(f"{Colors.GREEN}{Colors.BOLD}状态: 成功找到密码!{Colors.END}")
            sys.exit(0)
        else:
            print(f"{Colors.RED}状态: 未找到密码{Colors.END}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] 用户中断攻击{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] 错误: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()

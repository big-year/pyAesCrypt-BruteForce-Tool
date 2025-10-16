#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pyAesCrypt BruteForce Tool v1.0
高效的pyAesCrypt密码爆破工具
"""

import os
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import itertools
import string
import subprocess
from pathlib import Path

try:
    import pyAesCrypt
except ImportError:
    print("[!] pyAesCrypt 未安装. 正在自动安装...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyAesCrypt"])
    import pyAesCrypt

class Colors:
    """终端颜色定义"""
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
    """统计信息类"""
    def __init__(self):
        self.start_time = time.time()
        self.attempts = 0
        self.found = False
        self.password = None
        self.lock = threading.Lock()
    
    def increment(self):
        with self.lock:
            self.attempts += 1
    
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

class PyAesBruteForcer:
    """pyAesCrypt暴力破解器主类"""
    
    def __init__(self, target_file, output_file=None, threads=4, verbose=False):
        self.target_file = target_file
        self.output_file = output_file or "decrypted_output.txt"
        self.threads = threads
        self.verbose = verbose
        self.stats = Stats()
        self.stop_event = threading.Event()
        
        # 验证目标文件
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"目标文件不存在: {target_file}")
    
    def test_password(self, password):
        """测试单个密码"""
        if self.stop_event.is_set():
            return False
            
        try:
            # 尝试解密文件
            temp_output = f"{self.output_file}.tmp.{threading.get_ident()}"
            pyAesCrypt.decryptFile(self.target_file, temp_output, password, 64*1024)
            
            # 清理临时文件
            if os.path.exists(temp_output):
                os.remove(temp_output)
                
            return True
            
        except Exception:
            return False
        finally:
            self.stats.increment()
    
    def dictionary_attack(self, wordlist_file):
        """字典攻击模式"""
        print(f"{Colors.CYAN}[*] 启动字典攻击模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 字典文件: {wordlist_file}{Colors.END}")
        print(f"{Colors.BLUE}[*] 线程数: {self.threads}{Colors.END}")
        print()
        
        if not os.path.exists(wordlist_file):
            print(f"{Colors.RED}[!] 字典文件不存在: {wordlist_file}{Colors.END}")
            return False
        
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        print(f"{Colors.GREEN}[+] 加载了 {len(passwords)} 个密码{Colors.END}")
        
        return self._run_attack(passwords)
    
    def brute_force_attack(self, charset, min_length=1, max_length=8):
        """暴力破解攻击模式"""
        print(f"{Colors.CYAN}[*] 启动暴力破解模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 字符集: {charset[:50]}{'...' if len(charset) > 50 else ''}{Colors.END}")
        print(f"{Colors.BLUE}[*] 密码长度: {min_length}-{max_length}{Colors.END}")
        print(f"{Colors.BLUE}[*] 线程数: {self.threads}{Colors.END}")
        print()
        
        passwords = []
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                passwords.append(''.join(combo))
                # 分批处理，避免内存耗尽
                if len(passwords) >= 10000:
                    if self._run_attack(passwords):
                        return True
                    passwords = []
        
        if passwords:
            return self._run_attack(passwords)
        
        return False
    
    def mask_attack(self, mask):
        """掩码攻击模式"""
        print(f"{Colors.CYAN}[*] 启动掩码攻击模式{Colors.END}")
        print(f"{Colors.BLUE}[*] 掩码: {mask}{Colors.END}")
        print(f"{Colors.BLUE}[*] 线程数: {self.threads}{Colors.END}")
        print()
        
        passwords = self._generate_mask_passwords(mask)
        return self._run_attack(passwords)
    
    def _generate_mask_passwords(self, mask):
        """根据掩码生成密码列表"""
        charset_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.ascii_letters + string.digits + string.punctuation
        }
        
        # 解析掩码
        positions = []
        i = 0
        while i < len(mask):
            if mask[i:i+2] in charset_map:
                positions.append(charset_map[mask[i:i+2]])
                i += 2
            else:
                positions.append([mask[i]])
                i += 1
        
        # 生成所有可能的组合
        passwords = []
        for combo in itertools.product(*positions):
            passwords.append(''.join(combo))
            if len(passwords) >= 10000:  # 分批处理
                yield passwords
                passwords = []
        
        if passwords:
            yield passwords
    
    def _run_attack(self, passwords):
        """运行攻击"""
        print(f"{Colors.YELLOW}[*] 开始暴力破解...{Colors.END}")
        
        # 启动进度显示线程
        progress_thread = threading.Thread(target=self._show_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有任务
            future_to_password = {
                executor.submit(self.test_password, pwd): pwd 
                for pwd in passwords
            }
            
            # 处理结果
            for future in as_completed(future_to_password):
                if self.stop_event.is_set():
                    break
                    
                password = future_to_password[future]
                try:
                    result = future.result()
                    if result:
                        self.stats.set_found(password)
                        self.stop_event.set()
                        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] 密码找到: {password}{Colors.END}")
                        
                        # 执行最终解密
                        print(f"{Colors.YELLOW}[*] 正在解密文件...{Colors.END}")
                        pyAesCrypt.decryptFile(self.target_file, self.output_file, password, 64*1024)
                        print(f"{Colors.GREEN}[+] 文件已解密到: {self.output_file}{Colors.END}")
                        
                        return True
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.RED}[!] 错误测试密码 '{password}': {e}{Colors.END}")
        
        self.stop_event.set()
        print(f"\n{Colors.RED}[-] 未找到正确密码{Colors.END}")
        return False
    
    def _show_progress(self):
        """显示进度"""
        while not self.stop_event.is_set():
            stats = self.stats.get_stats()
            if stats['found']:
                break
                
            elapsed_str = time.strftime('%H:%M:%S', time.gmtime(stats['elapsed']))
            print(f"\r{Colors.CYAN}[*] 尝试: {stats['attempts']:,} | "
                  f"速度: {stats['rate']:.0f}/s | "
                  f"时间: {elapsed_str}{Colors.END}", end='', flush=True)
            
            time.sleep(1)

def create_sample_wordlist():
    """创建示例字典文件"""
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
    """打印工具横幅"""
    banner = rf"""{Colors.CYAN}{Colors.BOLD}
 ____        _            ____             _       
|  _ \ _   _| |_ ___  ___| __ ) _ __ _   _| |_ ___ 
| |_) | | | | __/ _ \/ __|  _ \| '__| | | | __/ _ \\
|  __/| |_| | ||  __/\__ \ |_) | |  | |_| | ||  __/
|_|    \__, |\__\___||___/____/|_|   \__,_|\__\___|
       |___/                                      
                                                  
    pyAesCrypt 高效暴力破解工具 v1.0
    
{Colors.END}{Colors.YELLOW}    [*] 支持字典攻击、暴力破解、掩码攻击
    [*] 多线程并发处理，高效快速
    [*] 类似Kali工具的简单界面
{Colors.END}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="pyAesCrypt 高效暴力破解工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""使用示例:
  字典攻击:
    python pyaes_bruteforce.py -f encrypted.aes -w wordlist.txt
    
  暴力破解:
    python pyaes_bruteforce.py -f encrypted.aes -b -c "0123456789" -l 4-6
    
  掩码攻击:
    python pyaes_bruteforce.py -f encrypted.aes -m "?d?d?d?d"  # 4位数字
    python pyaes_bruteforce.py -f encrypted.aes -m "admin?d?d" # admin+2位数字
    
掩码字符:
  ?l = 小写字母 (a-z)
  ?u = 大写字母 (A-Z) 
  ?d = 数字 (0-9)
  ?s = 特殊字符
  ?a = 所有字符
"""
    )
    
    parser.add_argument("-f", "--file", help="目标加密文件")
    parser.add_argument("-o", "--output", default="decrypted.txt", help="解密后输出文件 (默认: decrypted.txt)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="线程数 (默认: 4)")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    
    # 攻击模式
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-w", "--wordlist", help="字典文件路径")
    group.add_argument("-b", "--brute", action="store_true", help="暴力破解模式")
    group.add_argument("-m", "--mask", help="掩码攻击模式")
    group.add_argument("--create-wordlist", action="store_true", help="创建示例字典文件")
    
    # 暴力破解选项
    parser.add_argument("-c", "--charset", default="0123456789", help="暴力破解字符集 (默认: 数字)")
    parser.add_argument("-l", "--length", default="1-4", help="密码长度范围 (格式: min-max, 默认: 1-4)")
    
    args = parser.parse_args()
    
    if args.create_wordlist:
        create_sample_wordlist()
        return
    
    # 非create-wordlist模式下，file参数是必需的
    if not args.file:
        parser.error("参数 -f/--file 是必需的（除非使用 --create-wordlist）")
    
    try:
        bruteforcer = PyAesBruteForcer(
            target_file=args.file,
            output_file=args.output,
            threads=args.threads,
            verbose=args.verbose
        )
        
        success = False
        start_time = time.time()
        
        if args.wordlist:
            success = bruteforcer.dictionary_attack(args.wordlist)
        elif args.brute:
            # 解析长度范围
            min_len, max_len = map(int, args.length.split('-'))
            success = bruteforcer.brute_force_attack(args.charset, min_len, max_len)
        elif args.mask:
            # 对于掩码攻击，需要处理生成器
            for password_batch in bruteforcer._generate_mask_passwords(args.mask):
                if bruteforcer._run_attack(password_batch):
                    success = True
                    break
        
        # 显示最终统计
        elapsed = time.time() - start_time
        stats = bruteforcer.stats.get_stats()
        
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

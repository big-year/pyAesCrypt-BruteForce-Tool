#!/bin/bash

# pyAesCrypt BruteForce Tool - 快速安装脚本

echo "====================================="
echo "  pyAesCrypt 爆破工具 - 安装脚本"
echo "====================================="
echo

# 检查Python版本
echo "[*] 检查Python环境..."
python3 --version
if [ $? -ne 0 ]; then
    echo "[!] 错误: 未找到Python3"
    exit 1
fi

# 安装依赖
echo "[*] 安装依赖包..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] 错误: 依赖安装失败"
    exit 1
fi

# 设置执行权限
echo "[*] 设置执行权限..."
chmod +x pyaes_bruteforce.py
chmod +x test_demo.py

# 创建符号链接(可选)
echo "[*] 创建命令别名..."
echo "alias pyaes-bruteforce='python3 $(pwd)/pyaes_bruteforce.py'" >> ~/.bashrc

echo
echo "[+] 安装完成!"
echo
echo "使用方法:"
echo "1. 创建测试文件: python3 test_demo.py --create-test"
echo "2. 运行演示: python3 test_demo.py --demo"
echo "3. 开始爆破: python3 pyaes_bruteforce.py -f target.aes -w wordlist.txt"
echo
echo "更多帮助请查看: README.md"
echo

# pyAesCrypt BruteForce Tool

一个高效的pyAesCrypt密码爆破工具。

## 功能特性

- 🚀 **多种攻击模式**: 字典攻击、暴力破解、掩码攻击
- ⚡ **高性能**: 多线程并发处理，支持自定义线程数
- 📊 **实时监控**: 实时显示攻击进度、速度和统计信息
- 🎯 **智能停止**: 找到密码后自动停止攻击
- 🛠️ **易于使用**: 简洁的命令行界面，类似Kali工具
- 🎨 **彩色输出**: 清晰的彩色终端输出

## 安装要求

```bash
pip install pyAesCrypt
```

## 使用方法

### 基本语法

```bash
python pyaes_bruteforce.py -f <加密文件> [选项]
```

### 攻击模式

#### 1. 字典攻击

使用预定义的密码字典进行攻击：

```bash
# 使用自定义字典
python pyaes_bruteforce.py -f encrypted.aes -w passwords.txt

# 创建示例字典文件
python pyaes_bruteforce.py --create-wordlist
```

#### 2. 暴力破解

通过尝试所有可能的字符组合：

```bash
# 4位数字密码
python pyaes_bruteforce.py -f encrypted.aes -b -c "0123456789" -l "1-4"

# 字母+数字组合，3-5位
python pyaes_bruteforce.py -f encrypted.aes -b -c "abcdefghijklmnopqrstuvwxyz0123456789" -l "3-5"

# 常用字符集
python pyaes_bruteforce.py -f encrypted.aes -b -c "abc123!@#" -l "1-6"
```

#### 3. 掩码攻击

使用掩码模式进行智能攻击：

```bash
# 4位数字
python pyaes_bruteforce.py -f encrypted.aes -m "?d?d?d?d"

# admin + 2位数字
python pyaes_bruteforce.py -f encrypted.aes -m "admin?d?d"

# 2位大写字母 + 4位数字
python pyaes_bruteforce.py -f encrypted.aes -m "?u?u?d?d?d?d"

# 密码 + 年份
python pyaes_bruteforce.py -f encrypted.aes -m "password?d?d?d?d"
```

### 掩码字符说明

| 掩码 | 含义 | 字符集 |
|------|------|--------|
| `?l` | 小写字母 | a-z |
| `?u` | 大写字母 | A-Z |
| `?d` | 数字 | 0-9 |
| `?s` | 特殊字符 | !@#$%^&*() 等 |
| `?a` | 所有字符 | 字母+数字+特殊字符 |

### 高级选项

```bash
# 自定义线程数（提高速度）
python pyaes_bruteforce.py -f encrypted.aes -w passwords.txt -t 8

# 指定输出文件
python pyaes_bruteforce.py -f encrypted.aes -w passwords.txt -o decrypted_file.txt

# 详细输出模式
python pyaes_bruteforce.py -f encrypted.aes -w passwords.txt -v
```

## 使用示例

### 快速开始

1. **创建测试文件**:
```bash
# 创建一个测试文件并加密
echo "这是一个测试文件" > test.txt
python -c "import pyAesCrypt; pyAesCrypt.encryptFile('test.txt', 'test.aes', '123456', 64*1024)"
```

2. **创建字典文件**:
```bash
python pyaes_bruteforce.py --create-wordlist
```

3. **开始破解**:
```bash
python pyaes_bruteforce.py -f test.aes -w common_passwords.txt
```

### 实际场景示例

#### 场景1: 破解数字密码

```bash
# 尝试1-6位数字密码
python pyaes_bruteforce.py -f document.aes -b -c "0123456789" -l "1-6" -t 8
```

#### 场景2: 破解常见密码模式

```bash
# password + 年份 (如: password2023)
python pyaes_bruteforce.py -f file.aes -m "password?d?d?d?d"

# 名字 + 生日 (如: john1990)
python pyaes_bruteforce.py -f file.aes -m "john?d?d?d?d"
```

#### 场景3: 综合字典攻击

```bash
# 使用大型密码字典（如rockyou.txt）
python pyaes_bruteforce.py -f target.aes -w /usr/share/wordlists/rockyou.txt -t 16
```

## 性能优化建议

1. **线程数设置**: 根据CPU核心数调整，通常设置为核心数的2倍
2. **字典优化**: 使用有针对性的密码字典，按常用程度排序
3. **掩码策略**: 根据目标特点设计掩码，避免盲目暴力破解
4. **分段攻击**: 对于大规模攻击，可以分段进行

## 输出示例

```
 ____        _            ____             _       
|  _ \ _   _| |_ ___  ___| __ ) _ __ _   _| |_ ___ 
| |_) | | | | __/ _ \/ __|  _ \| '__| | | | __/ _ \\
|  __/| |_| | ||  __/\__ \ |_) | |  | |_| | ||  __/
|_|    \__, |\__\___||___/____/|_|   \__,_|\__\___|
       |___/                                      
                                                  
    pyAesCrypt 高效暴力破解工具 v1.0
    
    [*] 支持字典攻击、暴力破解、掩码攻击
    [*] 多线程并发处理，高效快速
    [*] 类似Kali工具的简单界面

[*] 启动字典攻击模式
[*] 字典文件: common_passwords.txt
[*] 线程数: 4

[+] 加载了 35 个密码
[*] 开始暴力破解...
[*] 尝试: 1,234 | 速度: 145/s | 时间: 00:00:08

[+] 密码找到: 123456
[*] 正在解密文件...
[+] 文件已解密到: decrypted.txt

=== 攻击完成 ===
总尝试次数: 1,856
总耗时: 00:00:12
平均速度: 154 密码/秒
状态: 成功找到密码!
```

## 注意事项

1. **合法使用**: 仅用于合法的密码恢复和安全测试
2. **性能影响**: 大规模攻击会消耗大量CPU和内存资源
3. **文件备份**: 在攻击前备份原始加密文件
4. **中断恢复**: 使用Ctrl+C可以随时中断攻击

## 常见问题

**Q: 如何提高破解速度？**
A: 增加线程数、使用SSD硬盘、优化字典内容

**Q: 支持哪些文件格式？**
A: 支持所有pyAesCrypt加密的文件（兼容AES Crypt格式）

**Q: 内存占用过高怎么办？**
A: 工具已采用分批处理策略，如仍有问题可减少线程数

## 许可证

本工具仅供学习和合法的安全测试使用。使用者需自行承担使用责任。

---
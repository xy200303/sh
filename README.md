# SSH Log Analyzer

https://img.shields.io/badge/license-MIT-blue.svg](LICENSE)
https://img.shields.io/badge/platform-Linux-lightgrey.svg](https://www.linux.org/)

一个强大的跨平台 SSH 登录日志分析工具，支持 Ubuntu/Debian 和 CentOS/RHEL 系统，能够统计 SSH 登录成功/失败次数、分析爆破 IP 来源，并提供历史数据总览。

## ✨ 特性

- 🔍 **自动系统识别**：自动检测 Ubuntu/Debian 或 CentOS/RHEL 系统，无需手动配置
- 📊 **全面统计分析**：
  - SSH 登录成功/失败总次数统计
  - 按 IP 地址排序的爆破源排名
  - 成功登录 IP 地址排名
- 📅 **灵活时间范围**：
  - 无参数时分析所有历史记录
  - 支持指定日期分析（YYYY-MM-DD 格式）
- 🎨 **直观输出**：彩色高亮显示，重要信息一目了然
- 🛡️ **安全可靠**：支持脚本内容预览，确保执行安全
- 🚀 **一键运行**：下载即可使用，无需复杂配置

## 🚀 快速开始

### 方法一：直接下载并执行（推荐）

```bash
# 使用 wget
sudo wget -O ssh_log.sh https://raw.githubusercontent.com/xy200303/sh/main/ssh_log.sh && sudo chmod +x ssh_log.sh && sudo ./ssh_log.sh

# 使用 curl
sudo curl -o ssh_log.sh https://raw.githubusercontent.com/xy200303/sh/main/ssh_log.sh && sudo chmod +x ssh_log.sh && sudo ./ssh_log.sh
```

### 方法二：分步执行（安全检查）

```bash
# 1. 下载脚本
sudo wget https://raw.githubusercontent.com/xy200303/sh/main/ssh_log.sh
# 或
sudo curl -O https://raw.githubusercontent.com/xy200303/sh/main/ssh_log.sh

# 2. 查看脚本内容（安全检查）
cat ssh_log.sh

# 3. 赋予执行权限
sudo chmod +x ssh_log.sh

# 4. 执行脚本
sudo ./ssh_log.sh
```

### 方法三：一键自动化脚本

```bash
# 下载并运行自动化脚本
wget https://raw.githubusercontent.com/xy200303/sh/main/auto_download_and_run.sh && chmod +x auto_download_and_run.sh && ./auto_download_and_run.sh
```

## 📖 使用说明

### 基本用法

```bash
# 分析所有历史 SSH 登录记录
sudo ./ssh_log.sh

# 分析指定日期的登录记录
sudo ./ssh_log.sh 2024-12-05
sudo ./ssh_log.sh "Dec 05"  # 也可使用日志日期格式
```

### 输出说明

脚本运行后会显示三个主要部分：

1. **总体统计**
   - ✅ 登录成功总次数
   - ❌ 登录失败总次数

2. **SSH 爆破源 IP 排名**
   - 按失败次数从高到低排序
   - 高频攻击 IP 会用红色高亮显示

3. **成功登录 IP 排名**
   - 按登录次数从高到低排序
   - 绿色显示所有成功登录的 IP

### 示例输出

```
==================================================
           SSH 登录统计报告 (Ubuntu/Debian)
==================================================

--- 总体统计 ---
  ✔ 登录成功总次数: 25
  ✘ 登录失败总次数: 158

--- SSH 爆破源 IP 排名 (按失败次数降序) ---
  失败次数    IP 地址
  ----------------------------------
     142     185.220.101.42
       8     192.168.1.100
       5     203.0.113.55

--- 成功登录 IP 排名 (按登录次数降序) ---
  成功次数    IP 地址
  ----------------------------------
       5     192.168.1.10
       2     10.0.0.5
```

## 🛠️ 系统要求

- **操作系统**：Ubuntu、Debian、CentOS、RHEL、Fedora
- **权限**：需要 root 权限（使用 sudo）
- **依赖**：`wget` 或 `curl`（用于下载）
- **Shell**：Bash 4.0+

## 🔧 支持的发行版

| 发行版 | 日志文件路径 | 状态 |
|--------|-------------|------|
| Ubuntu | `/var/log/auth.log` | ✅ 完全支持 |
| Debian | `/var/log/auth.log` | ✅ 完全支持 |
| CentOS | `/var/log/secure` | ✅ 完全支持 |
| RHEL | `/var/log/secure` | ✅ 完全支持 |
| Fedora | `/var/log/secure` | ✅ 完全支持 |

## 📋 常见问题

### Q: 脚本提示"不支持或未识别的 Linux 发行版"怎么办？

A: 请确认您的系统是基于 systemd 的主流发行版。如果是其他发行版（如 Arch Linux），可能需要手动修改脚本中的日志路径配置。

### Q: 为什么统计结果为 0？

A: 可能的原因：
1. 指定日期没有 SSH 登录记录
2. SSH 服务未运行
3. 日志轮转导致数据不在主日志文件中
4. 日期格式不匹配（建议使用 YYYY-MM-DD 格式）

### Q: 如何分析压缩的旧日志？

A: 当前版本只分析未压缩的日志文件。如需分析 `.gz` 压缩的日志，可以使用以下命令解压：
```bash
sudo gunzip /var/log/auth.log.1.gz  # Ubuntu/Debian
sudo gunzip /var/log/secure.1.gz   # CentOS/RHEL
```

## 🔒 安全说明

- 本工具仅用于日志分析，**不会修改任何系统文件**
- 建议在**生产环境使用前**先在测试环境验证
- 执行前可通过 `cat ssh_log.sh` 查看脚本内容确保安全
- 脚本仅读取日志文件，不会对系统造成安全风险

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交改动 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。

## 🙏 致谢

- 感谢所有为 Linux 运维安全做出贡献的开发者
- 灵感来源于日常运维工作中的实际需求

## 📞 联系方式

如有问题或建议，欢迎通过以下方式联系：
- 提交 https://github.com/xy200303/sh/issues
- 发送邮件至：[your-email@example.com]

---

⭐ 如果这个工具对您有帮助，请给个 Star 支持一下！

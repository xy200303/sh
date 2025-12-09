#!/bin/bash

# ==============================================================================
# Universal SSH 登录统计脚本 (终极版 - 自动识别系统)
# 功能:
#   1. 自动识别 Ubuntu/Debian 或 CentOS/RHEL 系统。
#   2. 无参数: 统计所有历史 SSH 登录记录。
#   3. 有参数: 统计指定日期的 SSH 登录记录。
# ==============================================================================

# =================== 函数定义 ===================
error_exit() { echo -e "${RED}错误: $1${NC}" >&2; exit 1; }
print_header() { echo -e "\n${BLUE}==================================================${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}==================================================${NC}"; }

# =================== 自动检测系统并设置路径 ===================
echo -e "${YELLOW}[*] 正在检测操作系统...${NC}"

if [ -f /etc/os-release ]; then
    # 使用 source 命令读取文件内容，然后用 grep 和 awk 提取值
    # shellcheck source=/dev/null
    source /etc/os-release
    
    OS_ID=$(echo "$ID" | tr '[:upper:]' '[:lower:]') # 转为小写，方便比较
    OS_PRETTY_NAME="$PRETTY_NAME"

    case "$OS_ID" in
        ubuntu|debian)
            MAIN_LOG="/var/log/auth.log"
            ROTATED_LOGS="/var/log/auth.log.*"
            SYSTEM_NAME="Ubuntu/Debian"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            MAIN_LOG="/var/log/secure"
            ROTATED_LOGS="/var/log/secure.*"
            SYSTEM_NAME="CentOS/RHEL/Fedora"
            ;;
        *)
            error_exit "不支持或未识别的 Linux 发行版: $OS_PRETTY_NAME ($ID)。无法继续。"
            ;;
    esac
    echo -e "${GREEN}[+] 检测到系统: $SYSTEM_NAME${NC}"
    echo -e "${GREEN}[+] 将使用日志文件: $MAIN_LOG${NC}"

else
    error_exit "无法找到 /etc/os-release 文件，无法确定操作系统类型。"
fi


# =================== 颜色定义 ===================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# =================== 主程序开始 ===================

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then error_exit "此脚本需要 root 权限。请使用 'sudo' 运行。"; fi

# 2. 检查主日志文件是否存在
if [ ! -f "$MAIN_LOG" ]; then error_exit "主日志文件 ${MAIN_LOG} 不存在。请确认 SSH 服务已在此系统上运行过。"; fi

# 3. 【核心逻辑】处理参数，决定分析范围
ANALYZE_MODE="specific_date"
LOG_SOURCES="$MAIN_LOG"

if [ -z "$1" ]; then
    ANALYZE_MODE="all_history"
    # 构建要分析的所有日志文件列表 (排除 .gz 压缩文件)
    LOG_SOURCES="$MAIN_LOG $(ls $ROTATED_LOGS 2>/dev/null | grep -vE '\.gz$')"
    echo -e "${MAGENTA}[*] 未指定日期，将分析所有可用的历史 SSH 登录记录...${NC}"
else
    INPUT_DATE="$1"
    if [[ "$INPUT_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        TARGET_DATE_STR=$(date -d "$INPUT_DATE" "+%b %e" | sed 's/^ *//')
        echo -e "${YELLOW}[*] 正在分析指定日期的日志: $INPUT_DATE (对应日志日期: '$TARGET_DATE_STR')${NC}"
    else
        TARGET_DATE_STR="$INPUT_DATE"
        echo -e "${YELLOW}[*] 正在分析指定日志日期: '$TARGET_DATE_STR'${NC}"
    fi
fi

# 检查我们找到的日志源文件是否真的存在
VALID_LOG_SOURCES=""
for log_file in $LOG_SOURCES; do
    if [ -f "$log_file" ]; then
        VALID_LOG_SOURCES="$VALID_LOG_SOURCES $log_file"
    fi
done

if [ -z "$VALID_LOG_SOURCES" ]; then
    error_exit "没有找到任何可供分析的日志文件。"
fi

# 4. 执行统计
if [ "$ANALYZE_MODE" = "all_history" ]; then
    print_header "SSH 登录历史总览 (所有可用日志 on $SYSTEM_NAME)"
else
    GREP_DATE_PATTERN="^$TARGET_DATE_STR\s\+.*sshd"
fi


# --- 数据统计函数 ---
run_analysis() {
    local source_files="$1"
    local description="$2"

    print_header "$description"

    local success_entries failed_entries
    if [ "$ANALYZE_MODE" = "all_history" ]; then
        success_entries=$(grep "sshd.*Accepted" $source_files | wc -l)
        failed_entries=$(grep "sshd.*Failed password" $source_files | wc -l)
    else
        success_entries=$(grep -E "$GREP_DATE_PATTERN" $source_files | grep "Accepted" | wc -l)
        failed_entries=$(grep -E "$GREP_DATE_PATTERN" $source_files | grep "Failed password" | wc -l)
    fi

    echo -e "  ${GREEN}✔ 登录成功总次数: $success_entries${NC}"
    echo -e "  ${RED}✘ 登录失败总次数: $failed_entries${NC}"

    # --- IP 分析 ---
    echo -e "\n--- SSH 爆破源 IP 排名 (按失败次数降序) ---"
    local failed_ips
    if [ "$ANALYZE_MODE" = "all_history" ]; then
        failed_ips=$(grep "sshd.*Failed password" $source_files | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr)
    else
        failed_ips=$(grep -E "$GREP_DATE_PATTERN" $source_files | grep "Failed password" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr)
    fi

    if [ -z "$failed_ips" ]; then
        echo "  无失败登录记录。"
    else
        echo -e "  ${YELLOW}失败次数\tIP 地址${NC}"; echo "  ----------------------------------"
        echo "$failed_ips" | head -20 | while read count ip; do
            if [ "$count" -gt 50 ]; then printf "  ${RED}%6d\t%s${NC}\n" "$count" "$ip"
            elif [ "$count" -gt 10 ]; then printf "  ${YELLOW}%6d\t%s${NC}\n" "$count" "$ip"
            else printf "  %6d\t%s\n" "$count" "$ip"; fi
        done
    fi
    
    echo -e "\n--- 成功登录 IP 排名 (按登录次数降序) ---"
    local success_ips
    if [ "$ANALYZE_MODE" = "all_history" ]; then
        success_ips=$(grep "sshd.*Accepted" $source_files | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr)
    else
        success_ips=$(grep -E "$GREP_DATE_PATTERN" $source_files | grep "Accepted" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr)
    fi

    if [ -z "$success_ips" ]; then
        echo "  无成功登录记录。"
    else
        echo -e "  ${YELLOW}成功次数\tIP 地址${NC}"; echo "  ----------------------------------"
        echo "$success_ips" | head -20 | while read count ip; do
            printf "  ${GREEN}%6d\t%s${NC}\n" "$count" "$ip"
        done
    fi
}


# --- 执行分析 ---
if [ "$ANALYZE_MODE" = "all_history" ]; then
    run_analysis "$VALID_LOG_SOURCES" "SSH 登录历史总览 (所有可用日志 on $SYSTEM_NAME)"
else
    run_analysis "$MAIN_LOG" "SSH 登录统计报告 (日期: $TARGET_DATE_STR)"
fi

echo -e "\n${BLUE}==================================================${NC}"
if [ "$ANALYZE_MODE" = "all_history" ]; then
    echo -e "${MAGENTA}提示: 可通过 'sudo bash $0 YYYY-MM-DD' 来分析指定日期的日志。${NC}"
fi
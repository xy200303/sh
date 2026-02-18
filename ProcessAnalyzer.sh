#!/bin/bash
# ProcessAnalyzer.sh - 专业版进程信息分析工具
# 作者：基于安全分析需求设计
# 版本：2.0
# 功能：全面分析指定进程的详细信息，包括源文件、启动链、网络、CPU、文件等

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 全局变量
PID=""
EXE_PATH=""
TOTAL_FDS=0
THREAD_COUNT=0
AVG_CPU=0
TCP_CONNECTIONS=""
UDP_CONNECTIONS=""
LISTEN_PORTS=""
SUSPICIOUS_COUNT=0
WARNINGS=0

# 函数：打印标题
print_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        ${BOLD}ProcessAnalyzer v2.0 - 专业进程分析工具${NC}        ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 函数：打印章节标题
print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  ${BOLD}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 函数：打印信息
print_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# 函数：打印警告
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

# 函数：打印错误
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 函数：打印提示
print_tip() {
    echo -e "${CYAN}[💡]${NC} $1"
}

# 函数：打印数据项
print_data() {
    local label=$1
    local value=$2
    printf "  ${MAGENTA}%-28s${NC} ${GREEN}%s${NC}\n" "$label:" "$value"
}

# 函数：打印带说明的数据项
print_data_explain() {
    local label=$1
    local value=$2
    local explain=$3
    printf "  ${MAGENTA}%-28s${NC} ${GREEN}%s${NC}\n" "$label:" "$value"
    if [ -n "$explain" ]; then
        printf "  ${CYAN}%-28s${NC} %s\n" "" "$explain"
    fi
}

# 函数：安全检查函数
check_suspicious() {
    local condition=$1
    local message=$2
    local severity=$3
    
    if eval "$condition"; then
        if [ "$severity" == "high" ]; then
            print_error "$message"
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 2))
        elif [ "$severity" == "medium" ]; then
            print_warning "$message"
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
        else
            print_info "$message"
        fi
    fi
}

# 检查参数
if [ $# -ne 1 ]; then
    print_header
    echo -e "${RED}错误：缺少进程ID参数${NC}"
    echo ""
    echo "用法: $0 <PID>"
    echo "示例: $0 1234"
    echo ""
    echo "提示：您可以使用以下命令查找进程ID："
    echo "  ps aux | grep <进程名>"
    echo "  pgrep <进程名>"
    echo "  pidof <进程名>"
    exit 1
fi

PID=$1

# 验证PID是否有效
if [ ! -d "/proc/$PID" ]; then
    print_header
    print_error "进程 $PID 不存在或无法访问"
    echo ""
    echo "可能的原因："
    echo "  1. 进程已经结束"
    echo "  2. PID输入错误"
    echo "  3. 权限不足（需要root权限访问某些进程）"
    echo ""
    echo "建议："
    echo "  - 使用 'ps aux' 查看当前运行的进程"
    echo "  - 使用 'sudo $0 $PID' 以root权限运行"
    exit 1
fi

print_header
print_info "开始分析进程 PID: ${BOLD}$PID${NC}"
print_info "分析时间: $(date '+%Y-%m-%d %H:%M:%S')"
print_info "分析用户: $(whoami)"
echo ""

# 1. 基本进程信息
print_section "1. 基本进程信息"

if [ -f "/proc/$PID/status" ]; then
    COMM=$(cat /proc/$PID/comm 2>/dev/null)
    STATE=$(grep -E "^State:" /proc/$PID/status | awk '{print $2}')
    PARENT_PID=$(grep -E "^PPid:" /proc/$PID/status | awk '{print $2}')
    PGID=$(grep -E "^Gid:" /proc/$PID/status | awk '{print $2}')
    SID=$(grep -E "^Sid:" /proc/$PID/status | awk '{print $2}')
    UID_REAL=$(grep -E "^Uid:" /proc/$PID/status | awk '{print $2}')
    UID_EFFECTIVE=$(grep -E "^Uid:" /proc/$PID/status | awk '{print $3}')
    THREADS=$(grep -E "^Threads:" /proc/$PID/status | awk '{print $2}')
    
    # 进程状态解释
    STATE_EXPLAIN=""
    case "$STATE" in
        R) STATE_EXPLAIN="正在运行或就绪" ;;
        S) STATE_EXPLAIN="可中断睡眠（等待事件）" ;;
        D) STATE_EXPLAIN="不可中断睡眠（通常在等待I/O）" ;;
        Z) STATE_EXPLAIN="僵尸进程（已终止但父进程未回收）" ;;
        T) STATE_EXPLAIN="已停止（收到SIGSTOP信号）" ;;
        t) STATE_EXPLAIN="跟踪停止（被调试器暂停）" ;;
        X) STATE_EXPLAIN="已死亡（不应出现）" ;;
        *) STATE_EXPLAIN="未知状态" ;;
    esac
    
    print_data "进程ID" "$PID"
    print_data "进程名称" "$COMM"
    print_data_explain "进程状态" "$STATE ($STATE_EXPLAIN)" ""
    print_data "父进程ID" "$PARENT_PID"
    print_data "进程组ID" "$PGID"
    print_data "会话ID" "$SID"
    
    # 获取用户名
    if command -v getent &>/dev/null; then
        USERNAME=$(getent passwd "$UID_REAL" 2>/dev/null | cut -d: -f1)
        print_data "运行用户" "$USERNAME (UID: $UID_REAL)"
    else
        print_data "实际用户ID" "$UID_REAL"
        print_data "有效用户ID" "$UID_EFFECTIVE"
    fi
    
    print_data "线程数" "$THREADS"
    THREAD_COUNT=$THREADS
    
    # 计算进程运行时间
    if [ -f "/proc/$PID/stat" ]; then
        START_TIME=$(awk '{print $22}' /proc/$PID/stat 2>/dev/null)
        BOOT_TIME=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
        HERTZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
        CURRENT_TIME=$(date +%s)
        PROCESS_START=$((BOOT_TIME + START_TIME / HERTZ))
        RUN_TIME=$((CURRENT_TIME - PROCESS_START))
        
        if [ $RUN_TIME -gt 86400 ]; then
            RUN_TIME_STR="$((RUN_TIME / 86400)) 天 $((RUN_TIME % 86400 / 3600)) 小时"
        elif [ $RUN_TIME -gt 3600 ]; then
            RUN_TIME_STR="$((RUN_TIME / 3600)) 小时 $((RUN_TIME % 3600 / 60)) 分钟"
        else
            RUN_TIME_STR="$((RUN_TIME / 60)) 分钟 $((RUN_TIME % 60)) 秒"
        fi
        print_data "运行时间" "$RUN_TIME_STR"
    fi
    
    # 优先级和nice值
    NICE=$(grep -E "^Nice:" /proc/$PID/status | awk '{print $2}')
    PRIO=$(grep -E "^voluntary_ctxt_switches:" /proc/$PID/status | awk '{print $2}' 2>/dev/null)
    print_data "Nice值" "$NICE (数值越小优先级越高)"
fi

# 2. 进程源文件信息
print_section "2. 进程源文件信息"

if [ -L "/proc/$PID/exe" ]; then
    EXE_PATH=$(readlink /proc/$PID/exe 2>/dev/null)
    print_data "可执行文件路径" "$EXE_PATH"
    
    if [ -f "$EXE_PATH" ]; then
        FILE_SIZE=$(du -h "$EXE_PATH" 2>/dev/null | awk '{print $1}')
        FILE_PERM=$(ls -ld "$EXE_PATH" 2>/dev/null | awk '{print $1}')
        FILE_OWNER=$(ls -ld "$EXE_PATH" 2>/dev/null | awk '{print $3":"$4}')
        FILE_MTIME=$(stat -c %y "$EXE_PATH" 2>/dev/null | cut -d'.' -f1)
        
        print_data "文件大小" "$FILE_SIZE"
        print_data "文件权限" "$FILE_PERM"
        print_data "文件所有者" "$FILE_OWNER"
        print_data "文件修改时间" "$FILE_MTIME"
        
        # 检查文件哈希
        if command -v md5sum &>/dev/null; then
            MD5_HASH=$(md5sum "$EXE_PATH" 2>/dev/null | awk '{print $1}')
            print_data "MD5哈希" "${MD5_HASH:0:16}..."
        fi
        if command -v sha256sum &>/dev/null; then
            SHA256_HASH=$(sha256sum "$EXE_PATH" 2>/dev/null | awk '{print $1}')
            print_data "SHA256哈希" "${SHA256_HASH:0:16}..."
        fi
        
        # 检查文件类型
        if command -v file &>/dev/null; then
            FILE_TYPE=$(file "$EXE_PATH" 2>/dev/null | cut -d: -f2-)
            print_data "文件类型" "$FILE_TYPE"
        fi
        
        # 安全检查：检查文件位置
        if echo "$EXE_PATH" | grep -q -E "^/tmp|^/dev/shm|^/var/tmp"; then
            print_warning "可执行文件位于临时目录（可疑！）"
            print_tip "正常程序通常不会在临时目录下运行"
        fi
    else
        print_warning "可执行文件已被删除或无法访问"
        print_tip "这可能是恶意软件的特征，程序运行后删除自身"
    fi
else
    print_warning "无法读取可执行文件路径"
    print_tip "这可能是内核进程或特殊系统进程"
fi

# 3. 完整命令行
print_section "3. 完整命令行"

if [ -f "/proc/$PID/cmdline" ]; then
    CMDLINE=$(tr '\0' ' ' < /proc/$PID/cmdline 2>/dev/null)
    if [ -n "$CMDLINE" ]; then
        print_info "完整命令行："
        echo ""
        echo "  ${CYAN}$CMDLINE${NC}"
        echo ""
        
        # 分析命令行参数
        CMDLINE_LEN=${#CMDLINE}
        if [ $CMDLINE_LEN -gt 200 ]; then
            print_info "命令行长度: $CMDLINE_LEN 字符"
        fi
        
        # 检查可疑参数
        if echo "$CMDLINE" | grep -qi -E "password|passwd|secret|token|key"; then
            print_warning "命令行中可能包含敏感信息（密码、密钥等）"
        fi
        
        if echo "$CMDLINE" | grep -qi -E "wget|curl|nc|netcat|bash.*-i|/bin/sh"; then
            print_warning "命令行包含网络或shell相关命令"
        fi
    else
        print_warning "无法读取命令行参数"
    fi
fi

# 4. 进程启动链分析
print_section "4. 进程启动链分析（进程树）"

print_info "完整的进程启动链："
echo ""
print_tip "这显示了进程是如何被启动的，从当前进程追溯到系统初始化进程"
echo ""

CURRENT_PID=$PID
DEPTH=0
MAX_DEPTH=25
PID_LIST=""

while [ $DEPTH -lt $MAX_DEPTH ] && [ -n "$CURRENT_PID" ] && [ "$CURRENT_PID" != "1" ] && [ -d "/proc/$CURRENT_PID" ]; do
    if [ -f "/proc/$CURRENT_PID/comm" ]; then
        COMM=$(cat /proc/$CURRENT_PID/comm 2>/dev/null)
        PARENT_PID=$(grep -E "^PPid:" /proc/$CURRENT_PID/status 2>/dev/null | awk '{print $2}')
        CMDLINE=$(tr '\0' ' ' < /proc/$CURRENT_PID/cmdline 2>/dev/null | head -c 80)
        
        # 缩进显示层级
        INDENT=""
        for i in $(seq 1 $DEPTH); do
            INDENT="$INDENT  │"
        done
        
        if [ $DEPTH -eq 0 ]; then
            echo -e "${RED}├─ [PID:$CURRENT_PID] ${BOLD}$COMM${NC} ${RED}(目标进程)${NC}"
        else
            echo "  $INDENT"
            echo "  $INDENT├─ [PID:$CURRENT_PID] $COMM"
        fi
        
        # 显示命令行
        if [ -n "$CMDLINE" ]; then
            echo "  $INDENT  └─ $CMDLINE"
        fi
        
        PID_LIST="$PID_LIST $CURRENT_PID"
        CURRENT_PID=$PARENT_PID
        DEPTH=$((DEPTH + 1))
    else
        break
    fi
done

# 显示init进程
if [ $DEPTH -lt $MAX_DEPTH ] && [ -n "$CURRENT_PID" ] && [ "$CURRENT_PID" == "1" ]; then
    INDENT=""
    for i in $(seq 1 $DEPTH); do
        INDENT="$INDENT  │"
    done
    echo "  $INDENT"
    echo "  $INDENT└─ [PID:1] ${GREEN}init/systemd${NC} ${GREEN}(系统初始化进程)${NC}"
fi

echo ""
print_info "进程链深度: $DEPTH 层"

# 5. 父进程详细信息
print_section "5. 父进程详细信息"

if [ -n "$PARENT_PID" ] && [ -d "/proc/$PARENT_PID" ]; then
    PARENT_COMM=$(cat /proc/$PARENT_PID/comm 2>/dev/null)
    PARENT_STATE=$(grep -E "^State:" /proc/$PARENT_PID/status | awk '{print $2}')
    
    print_data "父进程ID" "$PARENT_PID"
    print_data "父进程名称" "$PARENT_COMM"
    print_data "父进程状态" "$PARENT_STATE"
    
    if [ -L "/proc/$PARENT_PID/exe" ]; then
        PARENT_EXE=$(readlink /proc/$PARENT_PID/exe 2>/dev/null)
        print_data "父进程可执行文件" "$PARENT_EXE"
    fi
    
    if [ -f "/proc/$PARENT_PID/cmdline" ]; then
        PARENT_CMDLINE=$(tr '\0' ' ' < /proc/$PARENT_PID/cmdline 2>/dev/null | head -c 150)
        print_data "父进程命令行" "$PARENT_CMDLINE"
    fi
    
    # 检查父进程是否可疑
    if echo "$PARENT_COMM" | grep -qi -E "bash|sh|python|perl|ruby"; then
        print_tip "父进程是解释器，可能通过脚本启动"
    fi
else
    print_warning "无法获取父进程信息（父进程可能已结束）"
fi

# 6. CPU和内存使用情况
print_section "6. CPU和内存使用情况"

if [ -f "/proc/$PID/stat" ]; then
    STAT_DATA=$(cat /proc/$PID/stat 2>/dev/null)
    
    UTIME=$(echo $STAT_DATA | awk '{print $14}')
    STIME=$(echo $STAT_DATA | awk '{print $15}')
    CUTIME=$(echo $STAT_DATA | awk '{print $16}')
    CSTIME=$(echo $STAT_DATA | awk '{print $17}')
    VSIZE=$(echo $STAT_DATA | awk '{print $23}')
    RSS=$(echo $STAT_DATA | awk '{print $24}')
    
    HERTZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
    
    print_data "用户态CPU时间" "$((UTIME / HERTZ)) 秒"
    print_data "内核态CPU时间" "$((STIME / HERTZ)) 秒"
    print_data "子进程用户态时间" "$((CUTIME / HERTZ)) 秒"
    print_data "子进程内核态时间" "$((CSTIME / HERTZ)) 秒"
    print_data "总CPU时间" "$(( (UTIME + STIME) / HERTZ )) 秒"
    print_data "虚拟内存大小" "$((VSIZE / 1024 / 1024)) MB"
    print_data "常驻内存大小" "$((RSS * 4 / 1024)) MB"
    
    # 内存使用解释
    print_tip "虚拟内存是进程申请的内存总量，常驻内存是实际占用的物理内存"
fi

if [ -f "/proc/$PID/statm" ]; then
    STATM_DATA=$(cat /proc/$PID/statm 2>/dev/null)
    TOTAL_PAGES=$(echo $STATM_DATA | awk '{print $1}')
    RESIDENT_PAGES=$(echo $STATM_DATA | awk '{print $2}')
    SHARED_PAGES=$(echo $STATM_DATA | awk '{print $3}')
    TEXT_PAGES=$(echo $STATM_DATA | awk '{print $4}')
    
    PAGE_SIZE=$(getconf PAGESIZE 2>/dev/null || echo 4096)
    
    echo ""
    print_info "内存页统计："
    print_data "总内存页数" "$TOTAL_PAGES"
    print_data "常驻内存页数" "$RESIDENT_PAGES"
    print_data "共享内存页数" "$SHARED_PAGES"
    print_data "代码段页数" "$TEXT_PAGES"
fi

# 7. CPU使用率实时监控
print_section "7. CPU使用率实时监控"

print_info "采样5次CPU使用率（间隔1秒）："
echo ""
print_tip "这显示了进程当前的CPU使用情况，可以判断进程是否活跃"
echo ""

CPU_SAMPLES=0
TOTAL_CPU_PERCENT=0
MAX_CPU=0
MIN_CPU=100

for i in {1..5}; do
    if [ -f "/proc/$PID/stat" ]; then
        STAT_DATA=$(cat /proc/$PID/stat 2>/dev/null)
        UTIME=$(echo $STAT_DATA | awk '{print $14}')
        STIME=$(echo $STAT_DATA | awk '{print $15}')
        
        TOTAL_CPU=$(grep -E "^cpu " /proc/stat 2>/dev/null | awk '{print $2+$3+$4+$5+$6+$7+$8}')
        
        if [ $i -eq 1 ]; then
            PREV_UTIME=$UTIME
            PREV_STIME=$STIME
            PREV_TOTAL_CPU=$TOTAL_CPU
            sleep 1
            continue
        fi
        
        DELTA_UTIME=$((UTIME - PREV_UTIME))
        DELTA_STIME=$((STIME - PREV_STIME))
        DELTA_TOTAL=$((TOTAL_CPU - PREV_TOTAL_CPU))
        
        if [ $DELTA_TOTAL -gt 0 ]; then
            CPU_PERCENT=$(( (DELTA_UTIME + DELTA_STIME) * 100 / DELTA_TOTAL ))
        else
            CPU_PERCENT=0
        fi
        
        # 更新最大最小值
        if [ $CPU_PERCENT -gt $MAX_CPU ]; then
            MAX_CPU=$CPU_PERCENT
        fi
        if [ $CPU_PERCENT -lt $MIN_CPU ]; then
            MIN_CPU=$CPU_PERCENT
        fi
        
        # 根据CPU使用率使用不同颜色
        if [ $CPU_PERCENT -gt 80 ]; then
            COLOR="${RED}"
        elif [ $CPU_PERCENT -gt 50 ]; then
            COLOR="${YELLOW}"
        else
            COLOR="${GREEN}"
        fi
        
        printf "  采样 %d: CPU使用率 = ${COLOR}%3d%%${NC}\n" "$i" "$CPU_PERCENT"
        
        TOTAL_CPU_PERCENT=$((TOTAL_CPU_PERCENT + CPU_PERCENT))
        CPU_SAMPLES=$((CPU_SAMPLES + 1))
        
        PREV_UTIME=$UTIME
        PREV_STIME=$STIME
        PREV_TOTAL_CPU=$TOTAL_CPU
        
        if [ $i -lt 5 ]; then
            sleep 1
        fi
    fi
done

if [ $CPU_SAMPLES -gt 0 ]; then
    AVG_CPU=$((TOTAL_CPU_PERCENT / CPU_SAMPLES))
    echo ""
    print_data "平均CPU使用率" "$AVG_CPU%"
    print_data "最高CPU使用率" "$MAX_CPU%"
    print_data "最低CPU使用率" "$MIN_CPU%"
    
    # CPU使用率评估
    if [ $AVG_CPU -gt 80 ]; then
        print_warning "CPU使用率非常高！进程可能在进行密集计算或挖矿"
    elif [ $AVG_CPU -gt 50 ]; then
        print_warning "CPU使用率较高，建议关注"
    else
        print_info "CPU使用率正常"
    fi
fi

# 8. 网络连接分析
print_section "8. 网络连接分析"

NET_CMD=""
if command -v ss &>/dev/null; then
    NET_CMD="ss -tunp"
elif command -v netstat &>/dev/null; then
    NET_CMD="netstat -tunp"
else
    print_warning "未找到 ss 或 netstat 命令，跳过网络分析"
fi

if [ -n "$NET_CMD" ]; then
    echo ""
    print_info "进程 $PID 的网络连接："
    echo ""
    print_tip "网络连接可以显示进程是否在与其他主机通信"
    echo ""
    
    # TCP连接
    TCP_CONNECTIONS=$(eval $NET_CMD 2>/dev/null | grep -w "$PID" | grep -v grep | grep tcp)
    if [ -n "$TCP_CONNECTIONS" ]; then
        TCP_COUNT=$(echo "$TCP_CONNECTIONS" | wc -l)
        echo "  ${GREEN}TCP 连接 ($TCP_COUNT 个)：${NC}"
        echo "$TCP_CONNECTIONS" | while read line; do
            echo "    $line"
        done
        
        # 检查可疑端口
        if echo "$TCP_CONNECTIONS" | grep -q -E ":(3333|4444|5555|6666|7777|8888|9000|14433|14444)"; then
            print_warning "发现连接到已知挖矿端口！"
        fi
    else
        echo "  ${YELLOW}无TCP连接${NC}"
    fi
    echo ""
    
    # UDP连接
    UDP_CONNECTIONS=$(eval $NET_CMD 2>/dev/null | grep -w "$PID" | grep -v grep | grep udp)
    if [ -n "$UDP_CONNECTIONS" ]; then
        UDP_COUNT=$(echo "$UDP_CONNECTIONS" | wc -l)
        echo "  ${GREEN}UDP 连接 ($UDP_COUNT 个)：${NC}"
        echo "$UDP_CONNECTIONS" | while read line; do
            echo "    $line"
        done
    else
        echo "  ${YELLOW}无UDP连接${NC}"
    fi
    echo ""
    
    # 监听端口
    LISTEN_PORTS=$(eval $NET_CMD 2>/dev/null | grep -w "$PID" | grep -v grep | grep LISTEN)
    if [ -n "$LISTEN_PORTS" ]; then
        LISTEN_COUNT=$(echo "$LISTEN_PORTS" | wc -l)
        echo "  ${GREEN}监听端口 ($LISTEN_COUNT 个)：${NC}"
        echo "$LISTEN_PORTS" | while read line; do
            echo "    $line"
        done
    else
        echo "  ${YELLOW}无监听端口${NC}"
    fi
fi

# 9. 文件描述符分析
print_section "9. 文件描述符分析"

FD_DIR="/proc/$PID/fd"
if [ -d "$FD_DIR" ]; then
    TOTAL_FDS=$(ls -1 "$FD_DIR" 2>/dev/null | wc -l)
    print_data "打开的文件描述符总数" "$TOTAL_FDS"
    
    # 统计不同类型的文件描述符
    SOCKETS=$(ls -la "$FD_DIR" 2>/dev/null | grep socket | wc -l)
    PIPES=$(ls -la "$FD_DIR" 2>/dev/null | grep pipe | wc -l)
    ANON_INODES=$(ls -la "$FD_DIR" 2>/dev/null | grep anon_inode | wc -l)
    REGULAR_FILES=$((TOTAL_FDS - SOCKETS - PIPES - ANON_INODES))
    
    print_data "Socket数量" "$SOCKETS"
    print_data "管道数量" "$PIPES"
    print_data "匿名inode数量" "$ANON_INODES"
    print_data "常规文件数量" "$REGULAR_FILES"
    
    # 文件描述符数量评估
    if [ $TOTAL_FDS -gt 1024 ]; then
        print_warning "文件描述符数量过多，可能导致资源耗尽"
    elif [ $TOTAL_FDS -gt 500 ]; then
        print_warning "文件描述符数量较多"
    fi
    
    echo ""
    
    # 显示打开的文件列表（限制显示数量）
    print_info "打开的文件列表（前20个）："
    echo ""
    
    ls -la "$FD_DIR" 2>/dev/null | head -n 21 | tail -n 20 | while read line; do
        echo "  $line"
    done
    
    if [ $TOTAL_FDS -gt 20 ]; then
        echo "  ... 还有 $((TOTAL_FDS - 20)) 个文件描述符"
    fi
else
    print_warning "无法访问文件描述符目录（可能需要root权限）"
fi

# 10. 文件读写情况
print_section "10. 文件读写情况（I/O统计）"

IO_DIR="/proc/$PID/io"
if [ -f "$IO_DIR" ]; then
    print_info "I/O 统计信息："
    echo ""
    print_tip "这显示了进程的磁盘读写活动"
    echo ""
    
    while read -r key value; do
        case "$key" in
            rchar:)
                print_data "读取字节数（累计）" "$((value / 1024)) KB"
                ;;
            wchar:)
                print_data "写入字节数（累计）" "$((value / 1024)) KB"
                ;;
            syscr:)
                print_data "读取系统调用次数" "$value"
                ;;
            syscw:)
                print_data "写入系统调用次数" "$value"
                ;;
            read_bytes:)
                print_data "实际从磁盘读取" "$((value / 1024)) KB"
                ;;
            write_bytes:)
                print_data "实际写入磁盘" "$((value / 1024)) KB"
                ;;
            cancelled_write_bytes:)
                print_data "取消的写入操作" "$((value / 1024)) KB"
                ;;
        esac
    done < "$IO_DIR"
else
    print_warning "无法访问I/O统计信息（需要root权限）"
    print_tip "使用 sudo $0 $PID 获取完整信息"
fi

# 11. 打开的文件路径
print_section "11. 打开的文件路径"

if [ -d "$FD_DIR" ]; then
    print_info "打开的文件路径（前15个）："
    echo ""
    
    ls -la "$FD_DIR" 2>/dev/null | grep -v -E "(socket|pipe|anon_inode)" | head -n 16 | tail -n 15 | while read line; do
        FD_NUM=$(echo "$line" | awk '{print $9}')
        if [ -n "$FD_NUM" ] && [ -L "$FD_DIR/$FD_NUM" ]; then
            FILE_PATH=$(readlink "$FD_DIR/$FD_NUM" 2>/dev/null)
            echo "  FD $FD_NUM: $FILE_PATH"
        fi
    done
    
    # 检查是否打开敏感文件
    SENSITIVE_FILES=$(ls -la "$FD_DIR" 2>/dev/null | grep -E "(passwd|shadow|ssh|\.pem|\.key|\.crt)" | wc -l)
    if [ $SENSITIVE_FILES -gt 0 ]; then
        echo ""
        print_warning "进程可能打开了敏感文件（密码、密钥等）"
    fi
fi

# 12. 环境变量
print_section "12. 环境变量"

if [ -f "/proc/$PID/environ" ]; then
    TOTAL_ENV=$(tr '\0' '\n' < /proc/$PID/environ 2>/dev/null | wc -l)
    print_data "环境变量总数" "$TOTAL_ENV"
    echo ""
    
    print_info "环境变量（前20个）："
    echo ""
    
    tr '\0' '\n' < /proc/$PID/environ 2>/dev/null | head -n 20 | while read -r env_var; do
        # 隐藏敏感信息
        if echo "$env_var" | grep -qi -E "password|secret|token|key"; then
            echo "  ${YELLOW}$env_var${NC} ${RED}[敏感信息已隐藏]${NC}"
        else
            echo "  $env_var"
        fi
    done
    
    if [ $TOTAL_ENV -gt 20 ]; then
        echo "  ... 还有 $((TOTAL_ENV - 20)) 个环境变量"
    fi
fi

# 13. 线程信息
print_section "13. 线程信息"

TASK_DIR="/proc/$PID/task"
if [ -d "$TASK_DIR" ]; then
    THREAD_COUNT=$(ls -1 "$TASK_DIR" 2>/dev/null | wc -l)
    print_data "线程总数" "$THREAD_COUNT"
    
    # 线程数量评估
    if [ $THREAD_COUNT -gt 50 ]; then
        print_warning "线程数量非常多，可能是多线程服务器程序"
    elif [ $THREAD_COUNT -gt 10 ]; then
        print_info "多线程程序"
    fi
    
    echo ""
    
    print_info "线程列表："
    echo ""
    
    ls -1 "$TASK_DIR" 2>/dev/null | while read tid; do
        if [ -f "$TASK_DIR/$tid/comm" ]; then
            TCOMM=$(cat "$TASK_DIR/$tid/comm" 2>/dev/null)
            TSTATE=$(grep -E "^State:" "$TASK_DIR/$tid/status" 2>/dev/null | awk '{print $2}')
            printf "  ${GREEN}TID:%-8s${NC} 状态: %-5s 名称: %s\n" "$tid" "$TSTATE" "$TCOMM"
        fi
    done
fi

# 14. 安全信息
print_section "14. 安全信息"

if [ -f "/proc/$PID/status" ]; then
    CAP_EFFECTIVE=$(grep -E "^CapEffective:" /proc/$PID/status 2>/dev/null | awk '{print $2}')
    CAP_PERMITTED=$(grep -E "^CapPermitted:" /proc/$PID/status 2>/dev/null | awk '{print $2}')
    CAP_INHERITABLE=$(grep -E "^CapInheritable:" /proc/$PID/status 2>/dev/null | awk '{print $2}')
    CAP_BSET=$(grep -E "^CapBnd:" /proc/$PID/status 2>/dev/null | awk '{print $2}')
    
    print_data "有效能力集" "$CAP_EFFECTIVE"
    print_data "允许能力集" "$CAP_PERMITTED"
    print_data "可继承能力集" "$CAP_INHERITABLE"
    print_data "边界能力集" "$CAP_BSET"
    
    # 检查是否有特殊能力
    if [ "$CAP_EFFECTIVE" != "0000000000000000" ]; then
        print_warning "进程拥有特殊能力（capabilities）"
        print_tip "Capabilities是Linux的权限管理机制，可能允许进程执行特权操作"
    fi
    
    # 检查SELinux上下文
    if [ -f "/proc/$PID/attr/current" ]; then
        SELINUX_CONTEXT=$(cat /proc/$PID/attr/current 2>/dev/null)
        if [ -n "$SELINUX_CONTEXT" ] && [ "$SELINUX_CONTEXT" != "" ]; then
            print_data "SELinux上下文" "$SELINUX_CONTEXT"
        fi
    fi
fi

# 15. 资源限制
print_section "15. 资源限制"

if [ -f "/proc/$PID/limits" ]; then
    print_info "资源限制："
    echo ""
    
    cat /proc/$PID/limits 2>/dev/null | while read line; do
        echo "  $line"
    done
fi

# 16. 内存映射区域
print_section "16. 内存映射区域"

if [ -f "/proc/$PID/maps" ]; then
    TOTAL_MAPS=$(wc -l < /proc/$PID/maps 2>/dev/null)
    print_data "内存映射区域数量" "$TOTAL_MAPS"
    echo ""
    
    print_info "内存映射（前20行）："
    echo ""
    
    head -n 20 /proc/$PID/maps 2>/dev/null | while read line; do
        echo "  $line"
    done
    
    if [ $TOTAL_MAPS -gt 20 ]; then
        echo "  ... 还有 $((TOTAL_MAPS - 20)) 个映射区域"
    fi
    
    # 统计不同类型的映射
    echo ""
    print_info "内存映射类型统计："
    echo ""
    echo "  可执行代码段: $(grep 'r-xp' /proc/$PID/maps 2>/dev/null | wc -l) 个"
    echo "  可读数据段: $(grep 'r--p' /proc/$PID/maps 2>/dev/null | wc -l) 个"
    echo "  可读写数据段: $(grep 'rw-p' /proc/$PID/maps 2>/dev/null | wc -l) 个"
    echo "  共享库: $(grep '\.so' /proc/$PID/maps 2>/dev/null | wc -l) 个"
fi

# 17. 进程状态变化
print_section "17. 进程状态统计"

if [ -f "/proc/$PID/stat" ]; then
    VOLUNTARY_CTX=$(grep -E "^voluntary_ctxt_switches:" /proc/$PID/status | awk '{print $2}')
    NONVOLUNTARY_CTX=$(grep -E "^nonvoluntary_ctxt_switches:" /proc/$PID/status | awk '{print $2}')
    
    print_data "自愿上下文切换" "$VOLUNTARY_CTX"
    print_data "非自愿上下文切换" "$NONVOLUNTARY_CTX"
    print_data "总上下文切换" "$((VOLUNTARY_CTX + NONVOLUNTARY_CTX))"
    
    print_tip "上下文切换次数反映进程的活跃程度和系统负载"
fi

# 18. 信号处理
print_section "18. 信号处理"

if [ -f "/proc/$PID/status" ]; then
    SIGCATCH=$(grep -E "^SigCgt:" /proc/$PID/status | awk '{print $2}')
    SIGIGN=$(grep -E "^SigIgn:" /proc/$PID/status | awk '{print $2}')
    SIGBLK=$(grep -E "^SigBlk:" /proc/$PID/status | awk '{print $2}')
    
    print_data "捕获的信号掩码" "$SIGCATCH"
    print_data "忽略的信号掩码" "$SIGIGN"
    print_data "阻塞的信号掩码" "$SIGBLK"
fi

# 综合分析和总结
print_section "19. 综合安全分析"

print_info "进程 $PID 的完整分析已完成"
echo ""
print_info "关键发现和安全评估："
echo ""

# 重置计数器
SUSPICIOUS_COUNT=0

# 检查高CPU使用
check_suspicious "[ $AVG_CPU -gt 80 ]" "CPU使用率异常高 ($AVG_CPU%)，可能在进行密集计算或挖矿" "high"
check_suspicious "[ $AVG_CPU -gt 50 ]" "CPU使用率较高 ($AVG_CPU%)" "medium"

# 检查网络连接
if [ -n "$TCP_CONNECTIONS" ] || [ -n "$UDP_CONNECTIONS" ]; then
    print_info "进程有网络连接活动"
    
    # 检查可疑端口
    if echo "$TCP_CONNECTIONS" | grep -q -E ":(3333|4444|5555|6666|7777|8888|9000|14433|14444)"; then
        check_suspicious "true" "连接到已知挖矿端口！" "high"
    fi
fi

# 检查文件描述符数量
check_suspicious "[ $TOTAL_FDS -gt 500 ]" "打开的文件描述符数量较多 ($TOTAL_FDS)" "medium"
check_suspicious "[ $TOTAL_FDS -gt 1024 ]" "文件描述符数量过多 ($TOTAL_FDS)，可能导致资源耗尽" "high"

# 检查线程数量
check_suspicious "[ $THREAD_COUNT -gt 50 ]" "线程数量非常多 ($THREAD_COUNT)" "medium"

# 检查可执行文件位置
if [ -n "$EXE_PATH" ]; then
    if echo "$EXE_PATH" | grep -q -E "^/tmp|^/dev/shm|^/var/tmp"; then
        check_suspicious "true" "可执行文件位于可疑临时目录 ($EXE_PATH)" "high"
    fi
fi

# 检查进程状态
if [ "$STATE" == "Z" ]; then
    check_suspicious "true" "进程是僵尸进程，父进程未正确回收" "medium"
fi

# 检查特殊能力
if [ "$CAP_EFFECTIVE" != "0000000000000000" ]; then
    print_info "进程拥有特殊能力（capabilities）"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 风险等级评估
RISK_LEVEL="安全"
RISK_COLOR="${GREEN}"

if [ $SUSPICIOUS_COUNT -ge 4 ]; then
    RISK_LEVEL="高危"
    RISK_COLOR="${RED}"
elif [ $SUSPICIOUS_COUNT -ge 2 ]; then
    RISK_LEVEL="中危"
    RISK_COLOR="${YELLOW}"
elif [ $SUSPICIOUS_COUNT -ge 1 ]; then
    RISK_LEVEL="低危"
    RISK_COLOR="${YELLOW}"
fi

echo -e "  ${BOLD}风险等级评估：${RISK_COLOR} $RISK_LEVEL ${NC}"
echo ""

# 根据风险等级提供建议
if [ "$RISK_LEVEL" == "高危" ]; then
    print_error "发现多个可疑特征，建议立即采取行动！"
    echo ""
    echo "  建议操作："
    echo "  1. 立即终止进程: kill -9 $PID"
    echo "  2. 检查进程启动链，找到源头"
    echo "  3. 检查系统日志: /var/log/syslog, /var/log/auth.log"
    echo "  4. 检查定时任务: crontab -l, /etc/crontab"
    echo "  5. 检查系统服务: systemctl list-units --type=service"
    echo "  6. 使用专业安全工具扫描: chkrootkit, rkhunter"
    echo "  7. 隔离系统并进行全面安全审计"
elif [ "$RISK_LEVEL" == "中危" ]; then
    print_warning "发现一些需要注意的特征"
    echo ""
    echo "  建议操作："
    echo "  1. 持续监控进程行为"
    echo "  2. 检查进程的合法性"
    echo "  3. 查看进程的详细日志"
    echo "  4. 确认是否为预期的系统服务"
elif [ "$RISK_LEVEL" == "低危" ]; then
    print_warning "发现少量需要注意的特征"
    echo ""
    echo "  建议操作："
    echo "  1. 定期检查进程状态"
    echo "  2. 关注资源使用情况"
else
    print_info "未发现明显的可疑特征"
    echo ""
    echo "  建议："
    echo "  1. 继续正常监控"
    echo "  2. 定期运行此工具进行安全检查"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 快速参考命令
print_section "20. 快速参考命令"

echo "  常用进程管理命令："
echo "  ${CYAN}查看进程详情:${NC}     ps aux | grep $PID"
echo "  ${CYAN}查看进程树:${NC}       pstree -p $PID"
echo "  ${CYAN}查看网络连接:${NC}     ss -tunp | grep $PID"
echo "  ${CYAN}查看打开的文件:${NC}   lsof -p $PID"
echo "  ${CYAN}终止进程:${NC}         kill -15 $PID (优雅终止)"
echo "  ${CYAN}强制终止进程:${NC}     kill -9 $PID (强制终止)"
echo "  ${CYAN}查看进程状态:${NC}     cat /proc/$PID/status"
echo "  ${CYAN}查看进程映射:${NC}     cat /proc/$PID/maps"
echo ""

# 统计信息
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  ${BOLD}分析统计${NC}"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  分析的进程ID:     $PID"
echo "  发现的警告数:     $WARNINGS"
echo "  可疑特征数:       $SUSPICIOUS_COUNT"
echo "  风险等级:         $RISK_LEVEL"
echo "  分析时间:         $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# 结束信息
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${BOLD}分析完成${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}            感谢使用 ProcessAnalyzer v2.0                ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

#!/bin/bash
# ProcMinerHunter.sh - 深度挖矿程序检测工具
# 作者：基于安全分析需求设计
# 版本：2.0
# 功能：深度扫描挖矿的可执行文件、代码、配置文件和定时任务

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
MINING_PROCESSES=0
SUSPICIOUS_FILES=0
SUSPICIOUS_CONFIGS=0
SUSPICIOUS_CRONS=0
SUSPICIOUS_SERVICES=0
SUSPICIOUS_SCRIPTS=0
MINING_CONNECTIONS=0
TOTAL_THREATS=0

# 函数：打印标题
print_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}      ${BOLD}ProcMinerHunter v2.0 - 深度挖矿检测工具${NC}        ${CYAN}║${NC}"
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
}

# 函数：打印错误
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 函数：打印提示
print_tip() {
    echo -e "${CYAN}[💡]${NC} $1"
}

# 函数：打印发现
print_found() {
    echo -e "${MAGENTA}[🔍]${NC} $1"
}

# 函数：记录威胁
record_threat() {
    TOTAL_THREATS=$((TOTAL_THREATS + 1))
}

print_header
print_info "开始深度挖矿扫描"
print_info "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
print_info "系统主机名: $(hostname)"
print_info "当前用户: $(whoami)"
echo ""

# 配置参数
MIN_CPU_THRESHOLD=50.0
MINING_KEYWORDS="xmrig minerd cpuminer ccminer stratum cryptonight monero xmr eth zec btc ltc doge"
MINING_CONFIG_KEYWORDS="stratum tcp wallet.url pool.host pool.port mining.pooler donate cpu threads intensity config json conf cfg"
OBFUSCATION_KEYWORDS="base64 eval exec chr ord pack unpack gzinflate gzdeflate str_rot13 \$\{.*\} \$_GET \$_POST \$_REQUEST \$_COOKIE"
MINING_CODE_PATTERNS="cryptonight rx algo difficulty pool wallet worker pass stratum+tcp stratum+ssl"
CODE_INJECTION_KEYWORDS="eval exec system shell_exec passthru popen proc_open pcntl_exec assert create_function preg_replace.*e"
SUSPICIOUS_PATHS="/tmp /dev/shm /var/tmp /var/run /run /root/.cache /home/*/.cache"
KNOWN_POOL_PORTS="3333 4444 5555 6666 7777 8888 9000 14433 14444 8080 8181 9999 443 80"
KNOWN_POOL_DOMAINS="pool.hashvault.pro xmr-eu1.nanopool.org xmr-usa1.nanopool.org pool.supportxmr.com pool.minergate.com xmrpool.eu monerohash.com xmr.f2pool.com xmr-eu1.nano.pool xmr-usa1.nano pool.xmr.ru pool.leafy.cash pool.hashvault.to pool.hashvault.cc pool.hashvault.net pool.hashvault.io pool.gntl.uk xmr-eu.dwarfpool.com xmr-usa.dwarfpool.com xmr-asia.dwarfpool.com xmr.crypto-pool.fr xmr.poolto.be xmr-eu1.herominers.com xmr-usa1.herominers.com xmr-asia.herominers.com pool.monero.org xmr.pool.minergate.com xmr.crypto-pool.fr xmr-eu.nano.pool xmr-usa.nano.pool xmr-asia.nano.pool pool.supportxmr.com:443"
SUSPICIOUS_FILENAMES="xmrig minerd cpuminer ccminer"
SUSPICIOUS_EXTENSIONS=".sh .pl .rb .php .bin .elf .so .dll .exe"

# 1. 深度进程扫描
print_section "1. 深度进程扫描"

print_info "扫描所有进程，寻找挖矿特征..."
echo ""

MINING_PROCESSES=0
for pid in $(ls -d /proc/[0-9]*/ 2>/dev/null | cut -d/ -f3); do
    if [ -f "/proc/$pid/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
        comm=$(cat /proc/$pid/comm 2>/dev/null)
        exe_path=$(readlink /proc/$pid/exe 2>/dev/null)
        
        # 检查挖矿关键词
        is_mining=0
        for keyword in $MINING_KEYWORDS; do
            if echo "$cmdline" | grep -iq "$keyword"; then
                is_mining=1
                break
            fi
            if echo "$comm" | grep -iq "$keyword"; then
                is_mining=1
                break
            fi
        done
        
        if [ $is_mining -eq 1 ]; then
            print_error "发现挖矿进程！"
            echo "  PID: $pid"
            echo "  进程名: $comm"
            echo "  可执行文件: $exe_path"
            echo "  命令行: $cmdline"
            
            # 获取进程详细信息
            if [ -f "/proc/$pid/status" ]; then
                uid=$(grep -E "^Uid:" /proc/$pid/status | awk '{print $2}')
                if command -v getent &>/dev/null; then
                    username=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
                    echo "  运行用户: $username (UID: $uid)"
                fi
            fi
            
            MINING_PROCESSES=$((MINING_PROCESSES + 1))
            record_threat
            echo ""
        fi
    fi
done

if [ $MINING_PROCESSES -eq 0 ]; then
    print_info "未发现明确的挖矿进程"
else
    print_warning "发现 $MINING_PROCESSES 个挖矿进程"
fi

# 2. 高CPU进程分析
print_section "2. 高CPU进程分析"

print_info "检查高CPU占用的进程..."
echo ""

HIGH_CPU_PROCESSES=0
for pid in $(ls -d /proc/[0-9]*/ 2>/dev/null | cut -d/ -f3); do
    if [ -f "/proc/$pid/stat" ]; then
        utime=$(awk '{print $14}' /proc/$pid/stat 2>/dev/null)
        stime=$(awk '{print $15}' /proc/$pid/stat 2>/dev/null)
        
        if [ -n "$utime" ] && [ -n "$stime" ]; then
            total_time=$((utime + stime))
            if [ $total_time -gt 1000000 ]; then
                comm=$(cat /proc/$pid/comm 2>/dev/null)
                cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | head -c 150)
                exe_path=$(readlink /proc/$pid/exe 2>/dev/null)
                
                print_warning "发现高CPU进程"
                echo "  PID: $pid"
                echo "  进程名: $comm"
                echo "  CPU时间: $total_time"
                echo "  可执行文件: $exe_path"
                echo "  命令行: $cmdline"
                
                # 检查是否在可疑路径
                for path in $SUSPICIOUS_PATHS; do
                    if echo "$exe_path" | grep -q "^$path"; then
                        print_error "进程在可疑路径运行！"
                        record_threat
                        break
                    fi
                done
                
                HIGH_CPU_PROCESSES=$((HIGH_CPU_PROCESSES + 1))
                echo ""
            fi
        fi
    fi
done

if [ $HIGH_CPU_PROCESSES -eq 0 ]; then
    print_info "未发现异常高CPU进程"
else
    print_warning "发现 $HIGH_CPU_PROCESSES 个高CPU进程"
fi

# 3. 深度文件系统扫描
print_section "3. 深度文件系统扫描"

print_info "扫描可疑路径下的可执行文件..."
echo ""

SUSPICIOUS_FILES=0
for path in $SUSPICIOUS_PATHS; do
    if [ -d "$path" ]; then
        print_found "扫描目录: $path"
        
        # 查找可执行文件
        find "$path" -type f -executable 2>/dev/null | while read file; do
            filename=$(basename "$file")
            
            # 检查文件名是否可疑
            is_suspicious=0
            for pattern in $SUSPICIOUS_FILENAMES; do
                if echo "$filename" | grep -qiE "$pattern"; then
                    is_suspicious=1
                    break
                fi
            done
            
            # 检查文件内容
            if [ -f "$file" ]; then
                # 检测挖矿关键词
                if grep -qiE "$MINING_KEYWORDS" "$file" 2>/dev/null; then
                    print_error "发现挖矿关键词的可疑文件！"
                    echo "  文件路径: $file"
                    echo "  文件名: $filename"
                    echo "  检测到: 挖矿关键词"
                    is_suspicious=1
                fi
            fi
            
            if [ $is_suspicious -eq 1 ]; then
                # 获取文件信息
                if [ -f "$file" ]; then
                    file_size=$(du -h "$file" 2>/dev/null | awk '{print $1}')
                    file_perm=$(ls -ld "$file" 2>/dev/null | awk '{print $1}')
                    file_owner=$(ls -ld "$file" 2>/dev/null | awk '{print $3":"$4}')
                    echo "  文件大小: $file_size"
                    echo "  文件权限: $file_perm"
                    echo "  文件所有者: $file_owner"
                    
                    # 检查文件类型
                    if command -v file &>/dev/null; then
                        file_type=$(file "$file" 2>/dev/null | cut -d: -f2-)
                        echo "  文件类型: $file_type"
                    fi
                    
                    # 检查文件哈希
                    if command -v md5sum &>/dev/null; then
                        md5_hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
                        echo "  MD5哈希: ${md5_hash:0:16}..."
                    fi
                fi
                
                SUSPICIOUS_FILES=$((SUSPICIOUS_FILES + 1))
                record_threat
                echo ""
            fi
        done
    fi
done

# 扫描隐藏的可执行文件
print_found "扫描隐藏的可执行文件..."
find / -type f -name ".*" -executable 2>/dev/null | grep -v -E "^/(proc|sys|dev)" | while read file; do
    filename=$(basename "$file")
    
    # 检查文件名
    is_suspicious=0
    for pattern in $SUSPICIOUS_FILENAMES; do
        if echo "$filename" | grep -qiE "$pattern"; then
            is_suspicious=1
            break
        fi
    done
    
    # 检查文件内容
    if [ -f "$file" ]; then
        # 检测挖矿关键词
        if grep -qiE "$MINING_KEYWORDS" "$file" 2>/dev/null; then
            print_error "发现挖矿关键词的可疑文件！"
            echo "  文件路径: $file"
            echo "  文件名: $filename"
            echo "  检测到: 挖矿关键词"
            is_suspicious=1
        fi
    fi
    
    if [ $is_suspicious -eq 1 ]; then
        SUSPICIOUS_FILES=$((SUSPICIOUS_FILES + 1))
        record_threat
        echo ""
    fi
done

if [ $SUSPICIOUS_FILES -eq 0 ]; then
    print_info "未发现可疑可执行文件"
else
    print_warning "发现 $SUSPICIOUS_FILES 个可疑可执行文件"
fi

# 4. 挖矿配置文件扫描
print_section "4. 挖矿配置文件扫描"

print_info "扫描挖矿相关的配置文件..."
echo ""

SUSPICIOUS_CONFIGS=0

# 扫描常见的配置文件位置
CONFIG_PATHS="/etc /root /home/* /opt /usr/local/etc"
CONFIG_PATTERNS="*min* *mine* *pool* *xmrig* *cpuminer* *stratum* *.json *.conf *.cfg"

for path in $CONFIG_PATHS; do
    if [ -d "$path" ]; then
        for pattern in $CONFIG_PATTERNS; do
            find "$path" -name "$pattern" -type f 2>/dev/null | while read file; do
                # 检查文件内容是否包含挖矿配置
                if grep -qiE "$MINING_CONFIG_KEYWORDS" "$file" 2>/dev/null; then
                    print_error "发现挖矿配置文件！"
                    echo "  文件路径: $file"
                    echo "  文件名: $(basename $file)"
                    
                    # 显示部分内容
                    SUSPICIOUS_CONFIGS=$((SUSPICIOUS_CONFIGS + 1))
                    record_threat
                    echo ""
                fi
            done
        done
    fi
done

# 扫描用户目录下的隐藏配置文件
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        find "$user_home" -name ".*" -type f 2>/dev/null | while read file; do
            filename=$(basename "$file")
            # 检查隐藏配置文件
            if echo "$filename" | grep -qiE "min|pool|mine"; then
                if grep -qiE "$MINING_CONFIG_KEYWORDS" "$file" 2>/dev/null; then
                    print_error "发现隐藏的挖矿配置文件！"
                    echo "  文件路径: $file"
                    SUSPICIOUS_CONFIGS=$((SUSPICIOUS_CONFIGS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

if [ $SUSPICIOUS_CONFIGS -eq 0 ]; then
    print_info "未发现挖矿配置文件"
else
    print_warning "发现 $SUSPICIOUS_CONFIGS 个挖矿配置文件"
fi

# 5. 深度定时任务扫描
print_section "5. 深度定时任务扫描"

print_info "扫描所有用户的定时任务..."
echo ""

SUSPICIOUS_CRONS=0

# 扫描系统级定时任务
print_found "扫描系统级定时任务..."
SYSTEM_CRON_FILES="/etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*"

for cron_file in $SYSTEM_CRON_FILES; do
    if [ -f "$cron_file" ]; then
        # 检查是否包含挖矿关键词
        if grep -qiE "$MINING_KEYWORDS" "$cron_file" 2>/dev/null; then
            print_error "发现可疑的系统定时任务！"
            echo "  文件: $cron_file"
            SUSPICIOUS_CRONS=$((SUSPICIOUS_CRONS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 扫描用户级定时任务
print_found "扫描用户级定时任务..."
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        user_cron="$user_home/.crontab"
        
        if [ -f "$user_cron" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$user_cron" 2>/dev/null; then
                print_error "发现可疑的用户定时任务！"
                echo "  用户: $username"
                echo "  文件: $user_cron"
                SUSPICIOUS_CRONS=$((SUSPICIOUS_CRONS + 1))
                record_threat
                echo ""
            fi
        fi
    fi
done

# 检查crontab命令（需要root权限）
if [ "$(id -u)" -eq 0 ]; then
    print_found "检查所有用户的crontab..."
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab_output=$(crontab -u "$user" -l 2>/dev/null)
        if [ -n "$crontab_output" ]; then
            if echo "$crontab_output" | grep -qiE "$MINING_KEYWORDS"; then
                print_error "发现用户 $user 的可疑定时任务！"
                echo "  用户: $user"
                SUSPICIOUS_CRONS=$((SUSPICIOUS_CRONS + 1))
                record_threat
                echo ""
            fi
        fi
    done
else
    print_tip "需要root权限检查所有用户的crontab"
fi

if [ $SUSPICIOUS_CRONS -eq 0 ]; then
    print_info "未发现可疑定时任务"
else
    print_warning "发现 $SUSPICIOUS_CRONS 个可疑定时任务"
fi

# 6. 系统服务扫描
print_section "6. 系统服务扫描"

print_info "扫描系统服务中的挖矿程序..."
echo ""

SUSPICIOUS_SERVICES=0

if command -v systemctl &>/dev/null; then
    # 检查所有服务
    systemctl list-units --type=service --all 2>/dev/null | grep -E "loaded|active" | while read line; do
        service_name=$(echo "$line" | awk '{print $1}')
        
        # 检查服务描述和可执行文件
        service_file="/etc/systemd/system/$service_name"
        if [ -f "$service_file" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$service_file" 2>/dev/null; then
                print_error "发现可疑的系统服务！"
                echo "  服务名称: $service_name"
                echo "  服务文件: $service_file"
                echo "  状态: $(systemctl is-active $service_name 2>/dev/null)"
                SUSPICIOUS_SERVICES=$((SUSPICIOUS_SERVICES + 1))
                record_threat
                echo ""
            fi
        fi
    done
else
    print_warning "未找到systemctl命令"
fi

# 检查init.d脚本
if [ -d "/etc/init.d" ]; then
    print_found "检查init.d脚本..."
    for script in /etc/init.d/*; do
        if [ -f "$script" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$script" 2>/dev/null; then
                print_error "发现可疑的init.d脚本！"
                echo "  脚本: $script"
                SUSPICIOUS_SERVICES=$((SUSPICIOUS_SERVICES + 1))
                record_threat
                echo ""
            fi
        fi
    done
fi

if [ $SUSPICIOUS_SERVICES -eq 0 ]; then
    print_info "未发现可疑系统服务"
else
    print_warning "发现 $SUSPICIOUS_SERVICES 个可疑系统服务"
fi

# 7. 可疑脚本扫描
print_section "7. 可疑脚本扫描"

print_info "扫描可疑的脚本文件..."
echo ""

SUSPICIOUS_SCRIPTS=0

# 扫描常见脚本位置
SCRIPT_PATHS="/tmp /var/tmp /dev/shm /root /home/*"
SCRIPT_EXTENSIONS=".sh .py .pl .rb .php"

for path in $SCRIPT_PATHS; do
    if [ -d "$path" ]; then
        for ext in $SCRIPT_EXTENSIONS; do
            find "$path" -name "*$ext" -type f 2>/dev/null | while read script; do
                is_suspicious=0
                script_name=$(basename "$script")
                
                # 检查脚本内容 - 挖矿关键词
                if grep -qiE "$MINING_KEYWORDS" "$script" 2>/dev/null; then
                    print_error "发现可疑脚本文件！"
                    echo "  脚本路径: $script"
                    echo "  文件名: $script_name"
                    echo "  检测到: 挖矿关键词"
                    is_suspicious=1
                fi
                
                if [ $is_suspicious -eq 1 ]; then
                    SUSPICIOUS_SCRIPTS=$((SUSPICIOUS_SCRIPTS + 1))
                    record_threat
                    echo ""
                fi
            done
        done
    fi
done

# 扫描伪装成其他文件的脚本
print_found "扫描伪装的脚本文件..."
find / -type f -name ".*" -o -name ".*.sh" 2>/dev/null | grep -v -E "^/(proc|sys|dev)" | while read -r file; do
    if [ -n "$file" ] && [ -f "$file" ]; then
        # 检查文件头
        file_header=$(head -c 20 "$file" 2>/dev/null)
        if echo "$file_header" | grep -q "#!/"; then
            print_warning "发现可能伪装的脚本文件！"
            echo "  文件路径: $file"
            SUSPICIOUS_SCRIPTS=$((SUSPICIOUS_SCRIPTS + 1))
            record_threat
            echo ""
        fi
    fi
done

if [ $SUSPICIOUS_SCRIPTS -eq 0 ]; then
    print_info "未发现可疑脚本文件"
else
    print_warning "发现 $SUSPICIOUS_SCRIPTS 个可疑脚本文件"
fi

# 8. 深度网络连接扫描
print_section "8. 深度网络连接扫描"

print_info "扫描挖矿相关的网络连接..."
echo ""

MINING_CONNECTIONS=0

if command -v ss &>/dev/null; then
    NET_CMD="ss -tunp"
elif command -v netstat &>/dev/null; then
    NET_CMD="netstat -tunp"
else
    print_warning "未找到网络扫描命令"
    NET_CMD=""
fi

if [ -n "$NET_CMD" ]; then
    # 检查已知挖矿端口
    for port in $KNOWN_POOL_PORTS; do
        connections=$(eval $NET_CMD 2>/dev/null | grep ":$port" | grep -v grep)
        if [ -n "$connections" ]; then
            print_error "发现连接到挖矿端口 $port！"
            echo "  连接详情:"
            echo "$connections" | while read line; do
                echo "    $line"
            done
            MINING_CONNECTIONS=$((MINING_CONNECTIONS + 1))
            record_threat
            echo ""
        fi
    done
    
    # 检查已知挖矿域名
    for domain in $KNOWN_POOL_DOMAINS; do
        connections=$(eval $NET_CMD 2>/dev/null | grep "$domain" | grep -v grep)
        if [ -n "$connections" ]; then
            print_error "发现连接到挖矿域名 $domain！"
            echo "  连接详情:"
            echo "$connections" | while read line; do
                echo "    $line"
            done
            MINING_CONNECTIONS=$((MINING_CONNECTIONS + 1))
            record_threat
            echo ""
        fi
    done
fi

if [ $MINING_CONNECTIONS -eq 0 ]; then
    print_info "未发现挖矿相关的网络连接"
else
    print_warning "发现 $MINING_CONNECTIONS 个挖矿相关的网络连接"
fi

# 9. 全面启动脚本扫描
print_section "9. 全面启动脚本扫描"

print_info "扫描所有可能的启动脚本位置..."
echo ""

STARTUP_THREATS=0

# 9.1 Systemd服务
print_found "扫描Systemd服务..."
if command -v systemctl &>/dev/null; then
    # 扫描系统服务
    SYSTEMD_SERVICES="/etc/systemd/system/*.service /lib/systemd/system/*.service /usr/lib/systemd/system/*.service"
    for service_file in $SYSTEMD_SERVICES; do
        if [ -f "$service_file" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$service_file" 2>/dev/null; then
                print_error "发现可疑的Systemd服务！"
                echo "  服务文件: $service_file"
                echo "  服务名称: $(basename $service_file)"
                STARTUP_THREATS=$((STARTUP_THREATS + 1))
                record_threat
                echo ""
            fi
        fi
    done
    
    # 扫描用户服务
    for user_home in /home/*; do
        if [ -d "$user_home/.config/systemd/user" ]; then
            USER_SERVICES="$user_home/.config/systemd/user/*.service"
            for service_file in $USER_SERVICES; do
                if [ -f "$service_file" ]; then
                    if grep -qiE "$MINING_KEYWORDS" "$service_file" 2>/dev/null; then
                        print_error "发现可疑的用户Systemd服务！"
                        echo "  服务文件: $service_file"
                        echo "  用户: $(basename $user_home)"
                        STARTUP_THREATS=$((STARTUP_THREATS + 1))
                        record_threat
                        echo ""
                    fi
                fi
            done
        fi
    done
fi

# 9.2 SysV init脚本
print_found "扫描SysV init脚本..."
INIT_SCRIPTS="/etc/rc.local /etc/rc.d/rc.local /etc/init.d/* /etc/rc*.d/*"
for init_script in $INIT_SCRIPTS; do
    if [ -f "$init_script" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$init_script" 2>/dev/null; then
            print_error "发现可疑的SysV init脚本！"
            echo "  脚本文件: $init_script"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 9.3 Upstart任务
print_found "扫描Upstart任务..."
if [ -d "/etc/init" ]; then
    for upstart_file in /etc/init/*.conf; do
        if [ -f "$upstart_file" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$upstart_file" 2>/dev/null; then
                print_error "发现可疑的Upstart任务！"
                echo "  任务文件: $upstart_file"
                STARTUP_THREATS=$((STARTUP_THREATS + 1))
                record_threat
                echo ""
            fi
        fi
    done
fi

# 9.4 自动启动目录
print_found "扫描自动启动目录..."
AUTOSTART_DIRS="/etc/xdg/autostart/*.desktop /usr/share/autostart/*.desktop"
for autostart_file in $AUTOSTART_DIRS; do
    if [ -f "$autostart_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$autostart_file" 2>/dev/null; then
            print_error "发现可疑的自动启动项！"
            echo "  启动文件: $autostart_file"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 9.5 用户自动启动
print_found "扫描用户自动启动..."
for user_home in /home/*; do
    if [ -d "$user_home/.config/autostart" ]; then
        for autostart_file in $user_home/.config/autostart/*.desktop; do
            if [ -f "$autostart_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$autostart_file" 2>/dev/null; then
                    print_error "发现可疑的用户自动启动项！"
                    echo "  启动文件: $autostart_file"
                    echo "  用户: $(basename $user_home)"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 9.6 Shell配置文件
print_found "扫描Shell配置文件..."
# 系统级Shell配置
SYSTEM_SHELL_CONFIGS="/etc/profile /etc/profile.d/* /etc/bashrc /etc/zshrc /etc/csh.cshrc"
for shell_config in $SYSTEM_SHELL_CONFIGS; do
    if [ -f "$shell_config" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$shell_config" 2>/dev/null; then
            print_error "发现可疑的系统Shell配置！"
            echo "  配置文件: $shell_config"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
        
        # 深度扫描：检查是否包含挖矿程序执行命令
        if grep -qiE 'nohup|\.\/.*xmrig|\.\/.*minerd|\.\/.*cpuminer|\.\/.*ccminer' "$shell_config" 2>/dev/null; then
            print_error "发现Shell配置包含挖矿程序执行！"
            echo "  配置文件: $shell_config"
            echo "  检测到: 挖矿程序执行命令"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
        
        # 深度扫描：检查是否指向可疑目录
        if grep -qiE '(/tmp|/dev/shm|/var/tmp|/var/run|/run)' "$shell_config" 2>/dev/null; then
            print_warning "发现Shell配置指向可疑目录！"
            echo "  配置文件: $shell_config"
            echo "  检测到: 指向临时目录的执行"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
done

# 用户级Shell配置
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_SHELL_CONFIGS="$user_home/.bashrc $user_home/.bash_profile $user_home/.bash_logout $user_home/.profile $user_home/.zshrc $user_home/.zprofile $user_home/.zshenv $user_home/.zlogin $user_home/.zlogout $user_home/.cshrc $user_home/.tcshrc"
        for shell_config in $USER_SHELL_CONFIGS; do
            if [ -f "$shell_config" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$shell_config" 2>/dev/null; then
                    print_error "发现可疑的用户Shell配置！"
                    echo "  配置文件: $shell_config"
                    echo "  用户: $(basename $user_home)"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
                
                # 深度扫描：检查是否包含挖矿程序执行命令
                if grep -qiE 'nohup|\.\/.*xmrig|\.\/.*minerd|\.\/.*cpuminer|\.\/.*ccminer' "$shell_config" 2>/dev/null; then
                    print_error "发现用户Shell配置包含挖矿程序执行！"
                    echo "  配置文件: $shell_config"
                    echo "  用户: $(basename $user_home)"
                    echo "  检测到: 挖矿程序执行命令"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
                
                # 深度扫描：检查是否指向可疑目录
                if grep -qiE '(/tmp|/dev/shm|/var/tmp|/var/run|/run)' "$shell_config" 2>/dev/null; then
                    print_warning "发现用户Shell配置指向可疑目录！"
                    echo "  配置文件: $shell_config"
                    echo "  用户: $(basename $user_home)"
                    echo "  检测到: 指向临时目录的执行"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# Root用户Shell配置
ROOT_SHELL_CONFIGS="/root/.bashrc /root/.bash_profile /root/.bash_logout /root/.profile /root/.zshrc /root/.zprofile /root/.zshenv /root/.zlogin /root/.zlogout /root/.cshrc /root/.tcshrc"
for shell_config in $ROOT_SHELL_CONFIGS; do
    if [ -f "$shell_config" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$shell_config" 2>/dev/null; then
            print_error "发现可疑的root用户Shell配置！"
            echo "  配置文件: $shell_config"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
        
        # 深度扫描：检查是否包含挖矿程序执行命令
        if grep -qiE 'nohup|\.\/.*xmrig|\.\/.*minerd|\.\/.*cpuminer|\.\/.*ccminer' "$shell_config" 2>/dev/null; then
            print_error "发现root Shell配置包含挖矿程序执行！"
            echo "  配置文件: $shell_config"
            echo "  检测到: 挖矿程序执行命令"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
        
        # 深度扫描：检查是否指向可疑目录
        if grep -qiE '(/tmp|/dev/shm|/var/tmp|/var/run|/run)' "$shell_config" 2>/dev/null; then
            print_warning "发现root Shell配置指向可疑目录！"
            echo "  配置文件: $shell_config"
            echo "  检测到: 指向临时目录的执行"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 9.7 桌面环境启动
print_found "扫描桌面环境启动..."
# GNOME启动
for user_home in /home/*; do
    if [ -d "$user_home/.config/autostart" ]; then
        GNOME_AUTOSTART="$user_home/.config/autostart/*.desktop"
        for desktop_file in $GNOME_AUTOSTART; do
            if [ -f "$desktop_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$desktop_file" 2>/dev/null; then
                    print_error "发现可疑的GNOME自动启动项！"
                    echo "  启动文件: $desktop_file"
                    echo "  用户: $(basename $user_home)"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# KDE启动
for user_home in /home/*; do
    if [ -d "$user_home/.config/autostart" ]; then
        KDE_AUTOSTART="$user_home/.config/autostart/*.desktop"
        for desktop_file in $KDE_AUTOSTART; do
            if [ -f "$desktop_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$desktop_file" 2>/dev/null; then
                    print_error "发现可疑的KDE自动启动项！"
                    echo "  启动文件: $desktop_file"
                    echo "  用户: $(basename $user_home)"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 9.8 其他启动位置
print_found "扫描其他启动位置..."
OTHER_STARTUP="/etc/environment /etc/sysconfig/* /etc/default/*"
for startup_file in $OTHER_STARTUP; do
    if [ -f "$startup_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$startup_file" 2>/dev/null; then
            print_error "发现可疑的启动配置！"
            echo "  配置文件: $startup_file"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 9.9 SSH启动脚本
print_found "扫描SSH启动脚本..."
SSH_CONFIGS="/etc/ssh/sshd_config /etc/ssh/ssh_config"
for ssh_config in $SSH_CONFIGS; do
    if [ -f "$ssh_config" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$ssh_config" 2>/dev/null; then
            print_error "发现可疑的SSH配置！"
            echo "  配置文件: $ssh_config"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# SSH authorized_keys
for user_home in /home/*; do
    if [ -d "$user_home/.ssh" ]; then
        SSH_AUTHORIZED="$user_home/.ssh/authorized_keys"
        if [ -f "$SSH_AUTHORIZED" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$SSH_AUTHORIZED" 2>/dev/null; then
                print_error "发现可疑的SSH authorized_keys！"
                echo "  文件: $SSH_AUTHORIZED"
                echo "  用户: $(basename $user_home)"
                STARTUP_THREATS=$((STARTUP_THREATS + 1))
                record_threat
                echo ""
            fi
        fi
    fi
done

# Root SSH配置
ROOT_SSH="/root/.ssh/authorized_keys"
if [ -f "$ROOT_SSH" ]; then
    if grep -qiE "$MINING_KEYWORDS" "$ROOT_SSH" 2>/dev/null; then
        print_error "发现可疑的root SSH配置！"
        echo "  文件: $ROOT_SSH"
        STARTUP_THREATS=$((STARTUP_THREATS + 1))
        record_threat
        echo ""
    fi
fi

# 9.10 检查rc脚本
print_found "扫描rc脚本..."
if [ -d "/etc/rc.d" ]; then
    for rc_file in /etc/rc.d/*; do
        if [ -f "$rc_file" ]; then
            if grep -qiE "$MINING_KEYWORDS" "$rc_file" 2>/dev/null; then
                print_error "发现可疑的rc脚本！"
                echo "  脚本文件: $rc_file"
                STARTUP_THREATS=$((STARTUP_THREATS + 1))
                record_threat
                echo ""
            fi
        fi
    done
fi

if [ -d "/etc/rc*.d" ]; then
    for rc_dir in /etc/rc*.d; do
        if [ -d "$rc_dir" ]; then
            for rc_file in $rc_dir/*; do
                if [ -f "$rc_file" ]; then
                    if grep -qiE "$MINING_KEYWORDS" "$rc_file" 2>/dev/null; then
                        print_error "发现可疑的rc启动脚本！"
                        echo "  脚本文件: $rc_file"
                        STARTUP_THREATS=$((STARTUP_THREATS + 1))
                        record_threat
                        echo ""
                    fi
                fi
            done
        fi
    done
fi

# 9.11 检查xinit启动
print_found "扫描xinit启动..."
XINIT_FILES="/etc/X11/xinit/xinitrc /etc/X11/xinit/xserverrc"
for xinit_file in $XINIT_FILES; do
    if [ -f "$xinit_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$xinit_file" 2>/dev/null; then
            print_error "发现可疑的xinit配置！"
            echo "  配置文件: $xinit_file"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 用户xinit配置
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_XINIT="$user_home/.xinitrc $user_home/.xserverrc"
        for xinit_file in $USER_XINIT; do
            if [ -f "$xinit_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$xinit_file" 2>/dev/null; then
                    print_error "发现可疑的用户xinit配置！"
                    echo "  配置文件: $xinit_file"
                    echo "  用户: $(basename $user_home)"
                    STARTUP_THREATS=$((STARTUP_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 9.12 检查网络启动
print_found "扫描网络启动配置..."
NETWORK_CONFIGS="/etc/network/interfaces /etc/network/interfaces.d/* /etc/sysconfig/network-scripts/ifcfg-*"
for net_config in $NETWORK_CONFIGS; do
    if [ -f "$net_config" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$net_config" 2>/dev/null; then
            print_error "发现可疑的网络启动配置！"
            echo "  配置文件: $net_config"
            STARTUP_THREATS=$((STARTUP_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

if [ $STARTUP_THREATS -eq 0 ]; then
    print_info "未发现可疑启动项"
else
    print_warning "发现 $STARTUP_THREATS 个可疑启动项"
fi

# 10. 终端启动文件深度扫描
print_section "10. 终端启动文件深度扫描"

print_info "搜索所有打开终端时可能加载的文件..."
echo ""

TERMINAL_LOAD_THREATS=0

# 10.1 搜索环境变量文件
print_found "搜索环境变量文件..."
ENV_FILES="/etc/environment /etc/default/locale /etc/sysconfig/i18n"
for env_file in $ENV_FILES; do
    if [ -f "$env_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$env_file" 2>/dev/null; then
            print_error "发现环境变量文件包含挖矿关键词！"
            echo "  文件: $env_file"
            TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 10.2 搜索用户环境变量
print_found "搜索用户环境变量..."
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_ENV_FILES="$user_home/.environment $user_home/.env $user_home/.bash_environment"
        for env_file in $USER_ENV_FILES; do
            if [ -f "$env_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$env_file" 2>/dev/null; then
                    print_error "发现用户环境变量文件包含挖矿关键词！"
                    echo "  文件: $env_file"
                    echo "  用户: $(basename $user_home)"
                    TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 10.3 搜索登录脚本
print_found "搜索登录脚本..."
LOGIN_SCRIPTS="/etc/bash.bashrc /etc/bash.bash_logout /etc/bash.bash_login /etc/csh.login /etc/csh.logout /etc/zsh.login /etc/zsh.logout"
for login_script in $LOGIN_SCRIPTS; do
    if [ -f "$login_script" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$login_script" 2>/dev/null; then
            print_error "发现登录脚本包含挖矿关键词！"
            echo "  脚本: $login_script"
            TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 10.4 搜索用户登录脚本
print_found "搜索用户登录脚本..."
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_LOGIN_SCRIPTS="$user_home/.bash_login $user_home/.bash_logout $user_home/.zlogin $user_home/.zlogout"
        for login_script in $USER_LOGIN_SCRIPTS; do
            if [ -f "$login_script" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$login_script" 2>/dev/null; then
                    print_error "发现用户登录脚本包含挖矿关键词！"
                    echo "  脚本: $login_script"
                    echo "  用户: $(basename $user_home)"
                    TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 10.5 搜索X11资源文件
print_found "搜索X11资源文件..."
X11_RESOURCES="/etc/X11/Xresources /etc/X11/Xmodmap /etc/X11/xorg.conf"
for x11_file in $X11_RESOURCES; do
    if [ -f "$x11_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$x11_file" 2>/dev/null; then
            print_error "发现X11资源文件包含挖矿关键词！"
            echo "  文件: $x11_file"
            TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 10.6 搜索用户X11资源文件
print_found "搜索用户X11资源文件..."
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_X11_FILES="$user_home/.Xresources $user_home/.Xmodmap $user_home/.xprofile"
        for x11_file in $USER_X11_FILES; do
            if [ -f "$x11_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$x11_file" 2>/dev/null; then
                    print_error "发现用户X11资源文件包含挖矿关键词！"
                    echo "  文件: $x11_file"
                    echo "  用户: $(basename $user_home)"
                    TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

# 10.7 搜索其他配置文件
print_found "搜索其他配置文件..."
OTHER_CONFIGS="/etc/issue /etc/issue.net /etc/motd /etc/update-motd.d/* /etc/ssh/sshrc"
for config_file in $OTHER_CONFIGS; do
    if [ -f "$config_file" ]; then
        if grep -qiE "$MINING_KEYWORDS" "$config_file" 2>/dev/null; then
            print_error "发现配置文件包含挖矿关键词！"
            echo "  文件: $config_file"
            TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

# 10.8 搜索用户其他配置文件
print_found "搜索用户其他配置文件..."
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        USER_OTHER_CONFIGS="$user_home/.inputrc $user_home/.exrc $user_home/.viminfo $user_home/.lesskey"
        for config_file in $USER_OTHER_CONFIGS; do
            if [ -f "$config_file" ]; then
                if grep -qiE "$MINING_KEYWORDS" "$config_file" 2>/dev/null; then
                    print_error "发现用户配置文件包含挖矿关键词！"
                    echo "  文件: $config_file"
                    echo "  用户: $(basename $user_home)"
                    TERMINAL_LOAD_THREATS=$((TERMINAL_LOAD_THREATS + 1))
                    record_threat
                    echo ""
                fi
            fi
        done
    fi
done

if [ $TERMINAL_LOAD_THREATS -eq 0 ]; then
    print_info "未发现可疑的终端启动文件"
else
    print_warning "发现 $TERMINAL_LOAD_THREATS 个可疑的终端启动文件"
fi

# 11. 日志文件扫描
print_section "10. 日志文件扫描"

print_info "扫描系统日志中的挖矿活动..."
echo ""

LOG_THREATS=0

# 检查系统日志
LOG_FILES="/var/log/syslog /var/log/auth.log /var/log/secure /var/log/messages /var/log/kern.log"

for log_file in $LOG_FILES; do
    if [ -f "$log_file" ]; then
        mining_logs=$(grep -iE "$MINING_KEYWORDS" "$log_file" 2>/dev/null | tail -n 5)
        if [ -n "$mining_logs" ]; then
            print_error "发现日志中的挖矿活动！"
            echo "  日志文件: $log_file"
            LOG_THREATS=$((LOG_THREATS + 1))
            record_threat
            echo ""
        fi
    fi
done

if [ $LOG_THREATS -eq 0 ]; then
    print_info "未在日志中发现挖矿活动"
else
    print_warning "在日志中发现 $LOG_THREATS 处挖矿活动"
fi

# 综合分析报告
print_section "综合安全分析报告"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  ${BOLD}扫描统计${NC}"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  挖矿进程数:       $MINING_PROCESSES"
echo "  高CPU进程数:       $HIGH_CPU_PROCESSES"
echo "  可疑文件数:       $SUSPICIOUS_FILES"
echo "  挖矿配置文件数:   $SUSPICIOUS_CONFIGS"
echo "  可疑定时任务数:   $SUSPICIOUS_CRONS"
echo "  可疑系统服务数:   $SUSPICIOUS_SERVICES"
echo "  可疑脚本文件数:   $SUSPICIOUS_SCRIPTS"
echo "  挖矿网络连接数:   $MINING_CONNECTIONS"
echo "  可疑启动项数:     $STARTUP_THREATS"
echo "  终端启动文件数:   $TERMINAL_LOAD_THREATS"
echo "  日志威胁数:       $LOG_THREATS"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  总威胁数:         ${RED}$TOTAL_THREATS${NC}"
echo ""

# 风险等级评估
RISK_LEVEL="安全"
RISK_COLOR="${GREEN}"

if [ $MINING_PROCESSES -gt 0 ] || [ $TOTAL_THREATS -ge 15 ]; then
    RISK_LEVEL="高危"
    RISK_COLOR="${RED}"
elif [ $TOTAL_THREATS -ge 8 ]; then
    RISK_LEVEL="中危"
    RISK_COLOR="${YELLOW}"
elif [ $TOTAL_THREATS -ge 1 ]; then
    RISK_LEVEL="低危"
    RISK_COLOR="${YELLOW}"
fi

echo -e "  ${BOLD}风险等级评估：${RISK_COLOR} $RISK_LEVEL ${NC}"
echo ""

# 详细建议
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  ${BOLD}处理建议${NC}"
echo ""

if [ "$RISK_LEVEL" == "高危" ]; then
    print_error "系统存在严重安全威胁！"
    echo ""
    echo "  立即行动："
    echo "  1. 终止所有挖矿进程: kill -9 <PID>"
    echo "  2. 删除所有可疑文件: rm -f <文件路径>"
    echo "  3. 禁用可疑服务: systemctl disable <服务名>"
    echo "  4. 删除可疑定时任务: crontab -r"
    echo "  5. 检查并清理启动项"
    echo "  6. 更改所有用户密码"
    echo "  7. 隔离系统并进行全面安全审计"
    echo ""
    echo "  深度调查："
    echo "  - 检查系统日志: /var/log/syslog, /var/log/auth.log"
    echo "  - 检查登录日志: last, lastb"
    echo "  - 检查SSH配置: /etc/ssh/sshd_config"
    echo "  - 检查用户账户: /etc/passwd, /etc/shadow"
    echo "  - 使用专业工具: chkrootkit, rkhunter, lynis"
elif [ "$RISK_LEVEL" == "中危" ]; then
    print_warning "系统存在一些安全风险"
    echo ""
    echo "  建议操作："
    echo "  1. 仔细检查所有发现的威胁项"
    echo "  2. 验证可疑文件的合法性"
    echo "  3. 检查系统服务的配置"
    echo "  4. 审查定时任务的内容"
    echo "  5. 持续监控系统行为"
elif [ "$RISK_LEVEL" == "低危" ]; then
    print_warning "发现少量可疑项目"
    echo ""
    echo "  建议操作："
    echo "  1. 检查发现的可疑项目"
    echo "  2. 确认是否为误报"
    echo "  3. 定期运行此扫描工具"
else
    print_info "系统相对安全"
    echo ""
    echo "  建议："
    echo "  1. 定期运行此扫描工具进行监控"
    echo "  2. 保持系统和软件更新"
    echo "  3. 加强系统安全配置"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 快速参考命令
print_section "快速参考命令"

echo "  ${BOLD}进程管理${NC}:"
echo "  ${CYAN}查看进程:${NC}         ps aux | grep <关键词>"
echo "  ${CYAN}查看进程树:${NC}       pstree -p"
echo "  ${CYAN}终止进程:${NC}         kill -9 <PID>"
echo ""
echo "  ${BOLD}文件操作${NC}:"
echo "  ${CYAN}查找文件:${NC}         find / -name <文件名>"
echo "  ${CYAN}查看文件:${NC}         cat <文件路径>"
echo "  ${CYAN}删除文件:${NC}         rm -f <文件路径>"
echo ""
echo "  ${BOLD}定时任务${NC}:"
echo "  ${CYAN}查看定时任务:${NC}     crontab -l"
echo "  ${CYAN}编辑定时任务:${NC}     crontab -e"
echo "  ${CYAN}删除定时任务:${NC}     crontab -r"
echo ""
echo "  ${BOLD}系统服务${NC}:"
echo "  ${CYAN}查看服务:${NC}         systemctl list-units --type=service"
echo "  ${CYAN}停止服务:${NC}         systemctl stop <服务名>"
echo "  ${CYAN}禁用服务:${NC}         systemctl disable <服务名>"
echo ""
echo "  ${BOLD}网络连接${NC}:"
echo "  ${CYAN}查看连接:${NC}         ss -tunp"
echo "  ${CYAN}查看端口:${NC}         ss -tunlp"
echo "  ${CYAN}查看进程连接:${NC}     ss -tunp | grep <PID>"
echo ""
echo "  ${BOLD}安全扫描${NC}:"
echo "  ${CYAN}Rootkit检测:${NC}      sudo chkrootkit"
echo "  ${CYAN}Rootkit检测:${NC}      sudo rkhunter --check"
echo "  ${CYAN}病毒扫描:${NC}         sudo clamscan -r /"
echo "  ${CYAN}安全审计:${NC}         sudo lynis audit system"
echo ""

# 结束信息
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${BOLD}扫描完成${NC}                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}            感谢使用 ProcMinerHunter v2.0                ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

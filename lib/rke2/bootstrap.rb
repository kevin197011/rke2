# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require_relative 'config'
require_relative 'helper'
require_relative 'logger'

module RKE2
  # Bootstrap class for system initialization and performance optimization
  class Bootstrap
    include RKE2::Config

    attr_reader :logger, :helper, :config

    # Initialize bootstrap with configuration
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @helper = RKE2::Helper.new(logger: @logger)
      @config_file = config_file
      @config = nil
    end

    # Run bootstrap process for all nodes
    #
    # @param reboot [Boolean] Whether to reboot nodes after initialization
    # @return [Boolean] True if all nodes bootstrapped successfully
    def run(reboot: true)
      @logger.deploy('🚀 开始系统初始化和性能优化')

      load_configuration
      validate_configuration

      nodes = extract_all_nodes
      @logger.info("发现 #{nodes.length} 个节点需要初始化", { node_count: nodes.length })

      success_count = 0
      failed_nodes = []

      # Phase 1: Initialize all nodes
      @logger.info('📋 阶段 1: 系统初始化和优化')
      nodes.each_with_index do |node, index|
        @logger.step(index + 1, nodes.length, "初始化节点 #{node[:name]} (#{node[:ip]})")

        if bootstrap_node(node)
          success_count += 1
          @logger.success("节点 #{node[:name]} 初始化完成")
        else
          failed_nodes << node[:name]
          @logger.error("节点 #{node[:name]} 初始化失败")
        end
      end

      # Check initialization results
      if failed_nodes.any?
        @logger.error("❌ #{failed_nodes.length} 个节点初始化失败: #{failed_nodes.join(', ')}")
        @logger.info("✅ #{success_count} 个节点初始化成功")
        return false
      end

      @logger.success("🎉 所有 #{nodes.length} 个节点初始化完成！")

      # Phase 2: Reboot nodes if requested
      if reboot
        @logger.info('📋 阶段 2: 重启节点以应用优化配置')

        unless reboot_all_nodes(nodes)
          @logger.error('❌ 节点重启过程中出现问题')
          return false
        end

        @logger.success('🎉 所有节点已重启并恢复在线！')
      else
        @logger.info('ℹ️  跳过重启阶段')
        @logger.info('💡 建议手动重启所有节点以确保优化配置生效: sudo reboot')
      end

      true
    end

    # Bootstrap a single node
    #
    # @param node [Hash] Node configuration
    # @return [Boolean] True if bootstrap successful
    def bootstrap_node(node)
      @logger.time("节点 #{node[:name]} 初始化") do
        # Test connectivity first
        unless test_node_connectivity(node)
          @logger.error("节点 #{node[:name]} 连接测试失败")
          return false
        end

        # Generate and upload initialization script
        script_content = generate_init_script(node)
        script_path = "/tmp/rke2_init_#{node[:name]}_#{Time.now.to_i}.sh"

        # Upload script
        @logger.loading("上传初始化脚本到 #{node[:name]}")
        upload_result = @helper.ssh_upload_content(
          node[:ip],
          node[:username],
          script_content,
          script_path,
          node[:ssh_key]
        )

        unless upload_result[:success]
          @logger.error("脚本上传失败: #{upload_result[:error]}")
          return false
        end

        # Execute initialization script
        @logger.loading('执行初始化脚本')
        exec_result = @helper.ssh_exec(
          node[:ip],
          node[:username],
          "chmod +x #{script_path} && #{script_path}",
          node[:ssh_key]
        )

        # Cleanup script
        @helper.ssh_exec(node[:ip], node[:username], "rm -f #{script_path}", node[:ssh_key], skip_sudo: false)

        if exec_result[:success]
          @logger.info('初始化脚本执行完成', {
                         node: node[:name],
                         output_length: exec_result[:output].length
                       })

          # Log script output if in debug mode
          if @logger.logger.level <= ::Logger::DEBUG
            # Ensure output is properly encoded for logging
            safe_output = safe_encode_utf8(exec_result[:output])
            @logger.debug("初始化脚本输出:\n#{safe_output}")
          end

          # Verify initialization
          verify_node_initialization(node)
        else
          # Ensure error message is properly encoded
          safe_error = safe_encode_utf8(exec_result[:error].to_s)
          @logger.error('初始化脚本执行失败', {
                          node: node[:name],
                          error: safe_error,
                          exit_code: exec_result[:exit_code]
                        })
          false
        end
      end
    rescue StandardError => e
      @logger.error("节点 #{node[:name]} 初始化异常: #{e.message}")
      false
    end

    private

    # Safely encode string to UTF-8, handling binary data
    #
    # @param data [String] Input data that may contain binary content
    # @return [String] UTF-8 encoded string with invalid characters replaced
    def safe_encode_utf8(data)
      return '' if data.nil?
      return data if data.encoding == Encoding::UTF_8 && data.valid_encoding?

      # First force encoding to UTF-8, then clean up invalid characters
      data.force_encoding('UTF-8').scrub('?')
    rescue StandardError
      # Fallback: convert via binary encoding first
      data.encode('UTF-8', data.encoding, invalid: :replace, undef: :replace)
    end

    # Load configuration from file
    def load_configuration
      @logger.debug("加载配置文件: #{@config_file}")
      @config = RKE2::Config.load_config(@config_file)
      @logger.info('配置文件加载完成')
    rescue StandardError => e
      @logger.fatal("配置文件加载失败: #{e.message}")
      raise
    end

    # Validate configuration
    def validate_configuration
      @logger.debug('验证配置文件')

      raise ArgumentError, '配置文件中缺少 nodes 配置或格式错误' unless @config['nodes'] && @config['nodes'].is_a?(Array)

      raise ArgumentError, '配置文件中没有定义任何节点' if @config['nodes'].empty?

      @config['nodes'].each_with_index do |node, index|
        validate_node_config(node, index)
      end

      @logger.info('配置文件验证通过')
    end

    # Validate single node configuration
    #
    # @param node [Hash] Node configuration
    # @param index [Integer] Node index for error reporting
    def validate_node_config(node, index)
      required_fields = %w[name ip role]
      missing_fields = required_fields.select { |field| node[field].nil? || node[field].to_s.strip.empty? }

      raise ArgumentError, "节点 #{index + 1} 缺少必需字段: #{missing_fields.join(', ')}" unless missing_fields.empty?

      return if %w[server agent lb].include?(node['role'])

      raise ArgumentError, "节点 #{node['name']} 的角色 '#{node['role']}' 无效，必须是 server、agent 或 lb"
    end

    # Extract all nodes from configuration
    #
    # @return [Array<Hash>] Array of node configurations
    def extract_all_nodes
      @config['nodes'].map do |node|
        {
          name: node['name'],
          ip: node['ip'],
          role: node['role'],
          username: node['username'] || @config['username'] || 'root',
          ssh_key: node['ssh_key'] || @config['ssh_key'] || '~/.ssh/id_rsa'
        }
      end
    end

    # Test node connectivity
    #
    # @param node [Hash] Node configuration
    # @return [Boolean] True if connectivity test passes
    def test_node_connectivity(node)
      @logger.debug('测试节点连接', { node: node[:name], ip: node[:ip] })

      # Test host reachability
      unless @helper.host_reachable?(node[:ip], 22, 10)
        @logger.error("节点 #{node[:name]} (#{node[:ip]}) 不可达")
        return false
      end

      # Test SSH connection
      unless @helper.test_ssh_connection(node[:ip], node[:username], node[:ssh_key])
        @logger.error("节点 #{node[:name]} SSH 连接失败")
        return false
      end

      # Test sudo access
      unless @helper.test_sudo_access(node[:ip], node[:username], node[:ssh_key])
        @logger.error("节点 #{node[:name]} sudo 权限测试失败")
        return false
      end

      @logger.success("节点 #{node[:name]} 连接测试通过")
      true
    end

    # Generate initialization script for a node
    #
    # @param node [Hash] Node configuration
    # @return [String] Initialization script content
    def generate_init_script(node)
      <<~SCRIPT
        #!/bin/bash
        set -e

        # Color codes for output
        RED='\\033[0;31m'
        GREEN='\\033[0;32m'
        YELLOW='\\033[1;33m'
        BLUE='\\033[0;34m'
        NC='\\033[0m' # No Color

        # Logging functions
        log_info() {
            echo -e "${BLUE}ℹ️  $1${NC}"
        }

        log_success() {
            echo -e "${GREEN}✅ $1${NC}"
        }

        log_warning() {
            echo -e "${YELLOW}⚠️  $1${NC}"
        }

        log_error() {
            echo -e "${RED}❌ $1${NC}"
        }

        log_info "🔧 开始初始化节点 #{node[:name]}..."

        # Get system information
        log_info "📊 系统信息:"
        echo "  主机名: $(hostname)"
        echo "  系统版本: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
        echo "  内核版本: $(uname -r)"
        echo "  CPU 核心数: $(nproc)"
        echo "  内存大小: $(free -h | grep '^Mem:' | awk '{print $2}')"
        echo "  磁盘空间: $(df -h / | tail -1 | awk '{print $2}')"

        # Configure time synchronization
        log_info "🕐 配置时间同步..."
        configure_time_sync() {
            if command -v systemctl >/dev/null 2>&1; then
                if systemctl is-active --quiet systemd-timesyncd; then
                    log_success "systemd-timesyncd 已运行"
                elif command -v chrony >/dev/null 2>&1 || command -v chronyd >/dev/null 2>&1; then
                    log_info "📦 安装时间同步服务..."
                    if command -v apt-get >/dev/null 2>&1; then
                        apt-get update -qq && apt-get install -y chrony
                        systemctl enable chrony && systemctl restart chrony
                    elif command -v yum >/dev/null 2>&1; then
                        yum install -y chrony
                        systemctl enable chronyd && systemctl restart chronyd
                    elif command -v dnf >/dev/null 2>&1; then
                        dnf install -y chrony
                        systemctl enable chronyd && systemctl restart chronyd
                    fi
                    log_success "chrony 已安装并启用"
                    echo "  📊 chrony 状态: $(systemctl is-active chronyd 2>/dev/null || systemctl is-active chrony 2>/dev/null || echo 'unknown')"
                else
                    systemctl enable systemd-timesyncd && systemctl restart systemd-timesyncd
                    log_success "systemd-timesyncd 已启用"
                fi
            else
                log_warning "无法配置时间同步服务"
            fi
        }
        configure_time_sync

        # Configure timezone
        log_info "🌏 配置时区为香港时区..."
        configure_timezone() {
            # Set timezone to Asia/Hong_Kong
            if command -v timedatectl >/dev/null 2>&1; then
                timedatectl set-timezone Asia/Hong_Kong
                log_success "时区已设置为 Asia/Hong_Kong"
                echo "  🕐 当前时间: $(date)"
                echo "  🌏 时区信息: $(timedatectl show --property=Timezone --value 2>/dev/null || echo 'Asia/Hong_Kong')"
            else
                # Fallback for systems without timedatectl
                if [ -f /usr/share/zoneinfo/Asia/Hong_Kong ]; then
                    ln -sf /usr/share/zoneinfo/Asia/Hong_Kong /etc/localtime
                    echo "Asia/Hong_Kong" > /etc/timezone 2>/dev/null || true
                    log_success "时区已设置为 Asia/Hong_Kong (手动方式)"
                    echo "  🕐 当前时间: $(date)"
                else
                    log_warning "无法找到 Asia/Hong_Kong 时区文件"
                fi
            fi

            # Update hardware clock
            if command -v hwclock >/dev/null 2>&1; then
                hwclock --systohc 2>/dev/null || true
                log_info "硬件时钟已同步"
            fi
        }
        configure_timezone

        # Disable swap
        log_info "💾 禁用 swap..."
        swapoff -a 2>/dev/null || true
        sed -i '/swap/d' /etc/fstab 2>/dev/null || true
        log_success "swap 已禁用"

        # Configure kernel modules
        log_info "🔧 配置内核模块..."
        cat > /etc/modules-load.d/rke2.conf << 'EOF'
        overlay
        br_netfilter
        ip_vs
        ip_vs_rr
        ip_vs_wrr
        ip_vs_sh
        nf_conntrack
        EOF

        # Load modules
        modprobe overlay 2>/dev/null || true
        modprobe br_netfilter 2>/dev/null || true
        modprobe ip_vs 2>/dev/null || true
        modprobe ip_vs_rr 2>/dev/null || true
        modprobe ip_vs_wrr 2>/dev/null || true
        modprobe ip_vs_sh 2>/dev/null || true
        modprobe nf_conntrack 2>/dev/null || true
        log_success "内核模块已加载"

        # Configure system parameters
        log_info "⚡ 配置系统参数优化..."
        cat > /etc/sysctl.d/99-rke2.conf << 'EOF'
        # Network optimization
        net.bridge.bridge-nf-call-iptables = 1
        net.bridge.bridge-nf-call-ip6tables = 1
        net.ipv4.ip_forward = 1
        net.ipv4.conf.all.forwarding = 1
        net.ipv6.conf.all.forwarding = 1

        # Performance tuning
        net.core.somaxconn = 32768
        net.core.netdev_max_backlog = 16384
        net.core.rmem_default = 262144
        net.core.rmem_max = 16777216
        net.core.wmem_default = 262144
        net.core.wmem_max = 16777216
        net.ipv4.tcp_rmem = 4096 65536 16777216
        net.ipv4.tcp_wmem = 4096 65536 16777216
        net.ipv4.tcp_max_syn_backlog = 8096
        net.ipv4.tcp_slow_start_after_idle = 0

        # File system
        fs.file-max = 2097152
        fs.inotify.max_user_instances = 8192
        fs.inotify.max_user_watches = 1048576

        # Virtual memory
        vm.max_map_count = 262144
        vm.swappiness = 1
        vm.overcommit_memory = 1
        EOF

        sysctl --system >/dev/null 2>&1 || true
        log_success "系统参数优化已应用"

        # Configure system limits
        log_info "📈 配置系统限制..."
        cat > /etc/security/limits.d/99-rke2.conf << 'EOF'
        * soft nofile 1048576
        * hard nofile 1048576
        * soft nproc 1048576
        * hard nproc 1048576
        * soft core unlimited
        * hard core unlimited
        * soft memlock unlimited
        * hard memlock unlimited
        EOF
        log_success "系统限制已优化"

        # Configure firewall
        log_info "🔥 配置防火墙..."
        configure_firewall() {
            if command -v ufw >/dev/null 2>&1; then
                ufw --force reset >/dev/null 2>&1 || true
                ufw --force disable >/dev/null 2>&1 || true
            elif command -v firewall-cmd >/dev/null 2>&1; then
                systemctl stop firewalld 2>/dev/null || true
                systemctl disable firewalld 2>/dev/null || true
            elif command -v iptables >/dev/null 2>&1; then
                iptables -F 2>/dev/null || true
                iptables -X 2>/dev/null || true
                iptables -t nat -F 2>/dev/null || true
                iptables -t nat -X 2>/dev/null || true
            fi
        }
        configure_firewall
        log_success "防火墙已配置"

        # Install system tools
        log_info "📦 安装系统工具..."
        install_tools() {
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y curl wget htop iotop nethogs iftop rsync unzip
            elif command -v yum >/dev/null 2>&1; then
                yum install -y curl wget htop iotop nethogs iftop rsync unzip
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y curl wget htop iotop nethogs iftop rsync unzip
            elif command -v zypper >/dev/null 2>&1; then
                zypper install -y curl wget htop iotop nethogs iftop rsync unzip
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm curl wget htop iotop nethogs iftop rsync unzip
            fi
        }
        install_tools >/dev/null 2>&1 || true
        log_success "系统工具安装完成"

        # Optimize disk performance
        log_info "💿 优化磁盘性能..."
        optimize_disk() {
            for disk in $(lsblk -d -n -o NAME | grep -E '^[sv]d[a-z]$'); do
                if [ -f "/sys/block/$disk/queue/scheduler" ]; then
                    echo deadline > "/sys/block/$disk/queue/scheduler" 2>/dev/null || true
                    echo "  磁盘 $disk 设置为 deadline 调度器"
                fi
            done
        }
        optimize_disk
        log_success "磁盘调度器已优化"

        # Set hostname
        log_info "🏷️  设置主机名..."
        hostnamectl set-hostname #{node[:name]} 2>/dev/null || echo "#{node[:name]}" > /etc/hostname
        log_success "主机名已正确设置"

        # Optimize DNS
        log_info "🌐 优化 DNS 配置..."
        configure_dns() {
            # Backup original resolv.conf
            cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true

            # Configure DNS servers
            cat > /etc/resolv.conf << 'EOF'
        nameserver 8.8.8.8
        nameserver 8.8.4.4
        nameserver 114.114.114.114
        options timeout:2 attempts:3 rotate single-request-reopen
        EOF
        }
        configure_dns
        log_success "DNS 配置已优化"

        # Configure memory optimization
        log_info "🧠 配置内存优化..."
        # Disable transparent huge pages
        echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
        echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true

        # Add to startup
        cat > /etc/systemd/system/disable-thp.service << 'EOF'
        [Unit]
        Description=Disable Transparent Huge Pages (THP)
        DefaultDependencies=no
        After=sysinit.target local-fs.target
        Before=basic.target

        [Service]
        Type=oneshot
        ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag'

        [Install]
        WantedBy=basic.target
        EOF

        systemctl enable disable-thp.service 2>/dev/null || true
        log_success "透明大页已禁用"
        log_success "内存优化已配置"

        # System status check
        log_info "🔍 系统状态检查..."
        echo "  当前时间: $(date)"
        echo "  当前时区: $(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'unknown')"
        echo "  CPU 使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//' || echo 'unknown')"
        echo "  内存使用率: $(free | grep Mem | awk '{printf \"%.1f%%\", $3/$2 * 100.0}' || echo 'unknown')"
        echo "  磁盘使用率: $(df -h / | tail -1 | awk '{print $5}' || echo 'unknown')"
        echo "  系统负载: $(uptime | awk -F'load average:' '{print $2}' | xargs || echo 'unknown')"
        echo "  打开文件数限制: $(ulimit -n || echo 'unknown')"
        echo "  进程数限制: $(ulimit -u || echo 'unknown')"

        # Restart system services
        log_info "🔄 重启系统服务..."
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart systemd-sysctl 2>/dev/null || true
        log_success "系统服务已重启"

        log_success "🎉 节点 #{node[:name]} 初始化完成！"

        log_info "📈 性能优化摘要:"
        echo "  - ✅ 时间同步已配置"
        echo "  - ✅ 时区已设置为香港时区"
        echo "  - ✅ Swap 已禁用"
        echo "  - ✅ 内核模块已加载"
        echo "  - ✅ 系统参数已优化"
        echo "  - ✅ 系统限制已调整"
        echo "  - ✅ 防火墙已配置"
        echo "  - ✅ 系统工具已安装"
        echo "  - ✅ 磁盘性能已优化"
        echo "  - ✅ 主机名已设置"
        echo "  - ✅ DNS 已优化"
        echo "  - ✅ 内存优化已启用"

        log_info "💡 建议: 在继续部署前重启节点以确保所有优化生效"
        echo "   重启命令: sudo reboot"

        exit 0
      SCRIPT
    end

    # Verify node initialization
    #
    # @param node [Hash] Node configuration
    # @return [Boolean] True if verification passes
    def verify_node_initialization(node)
      @logger.debug('验证节点初始化', { node: node[:name] })

      verification_commands = {
        swap_disabled: 'cat /proc/swaps | wc -l',
        kernel_modules: "lsmod | grep -E '(overlay|br_netfilter)' | wc -l",
        sysctl_applied: 'sysctl net.bridge.bridge-nf-call-iptables',
        hostname_set: 'hostname',
        timezone_set: 'timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown"'
      }

      verification_results = {}

      verification_commands.each do |check, command|
        result = @helper.ssh_exec(node[:ip], node[:username], command, node[:ssh_key])
        verification_results[check] = {
          success: result[:success],
          output: result[:output]&.strip
        }
      end

      # Check results
      checks_passed = 0
      total_checks = verification_commands.length

      # Swap should be disabled (only header line in /proc/swaps)
      if verification_results[:swap_disabled][:success] &&
         verification_results[:swap_disabled][:output].to_i <= 1
        checks_passed += 1
        @logger.debug('✅ Swap 禁用检查通过')
      else
        @logger.debug('❌ Swap 禁用检查失败')
      end

      # Kernel modules should be loaded (at least 2 modules)
      if verification_results[:kernel_modules][:success] &&
         verification_results[:kernel_modules][:output].to_i >= 2
        checks_passed += 1
        @logger.debug('✅ 内核模块检查通过')
      else
        @logger.debug('❌ 内核模块检查失败')
      end

      # Sysctl should return 1
      if verification_results[:sysctl_applied][:success] &&
         verification_results[:sysctl_applied][:output].include?('= 1')
        checks_passed += 1
        @logger.debug('✅ 系统参数检查通过')
      else
        @logger.debug('❌ 系统参数检查失败')
      end

      # Hostname should match
      if verification_results[:hostname_set][:success] &&
         verification_results[:hostname_set][:output] == node[:name]
        checks_passed += 1
        @logger.debug('✅ 主机名检查通过')
      else
        @logger.debug('❌ 主机名检查失败')
      end

      # Timezone should be set to Asia/Hong_Kong
      if verification_results[:timezone_set][:success] &&
         verification_results[:timezone_set][:output].include?('Asia/Hong_Kong')
        checks_passed += 1
        @logger.debug('✅ 时区检查通过')
      else
        @logger.debug('❌ 时区检查失败')
      end

      success_rate = (checks_passed.to_f / total_checks * 100).round(1)
      @logger.info("验证完成: #{checks_passed}/#{total_checks} 项检查通过 (#{success_rate}%)", {
                     node: node[:name],
                     checks_passed: checks_passed,
                     total_checks: total_checks,
                     success_rate: success_rate
                   })

      checks_passed >= (total_checks * 0.75).ceil # At least 75% checks should pass
    end

    # Reboot all nodes and wait for them to come back online
    #
    # @param nodes [Array<Hash>] Array of node configurations
    # @return [Boolean] True if all nodes rebooted successfully
    def reboot_all_nodes(nodes)
      @logger.info("准备重启 #{nodes.length} 个节点...")

      # Phase 1: Initiate reboot on all nodes
      @logger.loading('发送重启命令到所有节点...')
      reboot_results = {}

      nodes.each do |node|
        @logger.debug("发送重启命令到节点 #{node[:name]} (#{node[:ip]})")

        # Send reboot command (don't wait for response as connection will drop)
        @helper.ssh_exec(
          node[:ip],
          node[:username],
          'sleep 2 && reboot',
          node[:ssh_key],
          timeout: 10
        )

        reboot_results[node[:name]] = {
          node: node,
          initiated: true
        }

        @logger.debug("重启命令已发送到节点 #{node[:name]}")
      end

      @logger.success("重启命令已发送到所有 #{nodes.length} 个节点")

      # Phase 2: Wait for nodes to go offline
      @logger.info('等待节点关机...')
      sleep 10 # Initial wait for reboot to start

      offline_nodes = []
      max_offline_wait = 120 # 2 minutes max wait for offline
      offline_start_time = Time.now

      while offline_nodes.length < nodes.length && (Time.now - offline_start_time) < max_offline_wait
        nodes.each do |node|
          next if offline_nodes.include?(node[:name])

          unless @helper.host_reachable?(node[:ip], 22, 3)
            offline_nodes << node[:name]
            @logger.debug("节点 #{node[:name]} 已离线")
          end
        end

        next unless offline_nodes.length < nodes.length

        remaining = nodes.length - offline_nodes.length
        @logger.debug("等待 #{remaining} 个节点离线... (#{(Time.now - offline_start_time).to_i}s)")
        sleep 5
      end

      if offline_nodes.length < nodes.length
        missing_offline = nodes.reject { |n| offline_nodes.include?(n[:name]) }.map { |n| n[:name] }
        @logger.warn("以下节点未检测到离线状态: #{missing_offline.join(', ')}")
      else
        @logger.success('所有节点已离线，开始等待重启完成')
      end

      # Phase 3: Wait for nodes to come back online
      @logger.info('等待节点重启完成...')
      online_nodes = []
      max_online_wait = 300 # 5 minutes max wait for online
      online_start_time = Time.now

      while online_nodes.length < nodes.length && (Time.now - online_start_time) < max_online_wait
        nodes.each do |node|
          next if online_nodes.include?(node[:name])

          next unless wait_for_node_online(node)

          online_nodes << node[:name]
          elapsed = (Time.now - online_start_time).to_i
          @logger.success("节点 #{node[:name]} 已恢复在线 (用时 #{elapsed}s)")
        end

        next unless online_nodes.length < nodes.length

        remaining = nodes.length - online_nodes.length
        elapsed = (Time.now - online_start_time).to_i
        @logger.loading("等待 #{remaining} 个节点恢复在线... (已等待 #{elapsed}s)")
        sleep 10
      end

      # Check final results
      if online_nodes.length == nodes.length
        total_time = (Time.now - offline_start_time).to_i
        @logger.success("所有 #{nodes.length} 个节点重启完成 (总用时 #{total_time}s)")

        # Verify nodes after reboot
        verify_nodes_after_reboot(nodes)

        true
      else
        failed_nodes = nodes.reject { |n| online_nodes.include?(n[:name]) }.map { |n| n[:name] }
        @logger.error("以下节点重启后未能恢复在线: #{failed_nodes.join(', ')}")
        @logger.info("已恢复在线的节点: #{online_nodes.join(', ')}") if online_nodes.any?
        false
      end
    end

    # Wait for a specific node to come back online after reboot
    #
    # @param node [Hash] Node configuration
    # @param timeout [Integer] Maximum wait time in seconds
    # @return [Boolean] True if node comes online
    def wait_for_node_online(node, timeout: 30)
      # First check if host is reachable
      return false unless @helper.host_reachable?(node[:ip], 22, timeout)

      # Then verify SSH connection
      max_attempts = 3
      attempt = 0

      while attempt < max_attempts
        return true if @helper.test_ssh_connection(node[:ip], node[:username], node[:ssh_key])

        attempt += 1
        sleep 5 if attempt < max_attempts
      end

      false
    end

    # Verify nodes after reboot to ensure optimizations are still applied
    #
    # @param nodes [Array<Hash>] Array of node configurations
    def verify_nodes_after_reboot(nodes)
      @logger.info('验证重启后的节点状态...')

      verification_results = {}

      nodes.each do |node|
        @logger.debug("验证节点 #{node[:name]} 重启后状态")

        # Quick verification of key settings
        verification_commands = {
          hostname: 'hostname',
          swap_status: 'cat /proc/swaps | wc -l',
          kernel_modules: "lsmod | grep -E '(overlay|br_netfilter)' | wc -l",
          transparent_hugepage: 'cat /sys/kernel/mm/transparent_hugepage/enabled',
          timezone: 'timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown"'
        }

        node_results = {}
        verification_commands.each do |check, command|
          result = @helper.ssh_exec(node[:ip], node[:username], command, node[:ssh_key])
          node_results[check] = {
            success: result[:success],
            output: result[:output]&.strip
          }
        end

        verification_results[node[:name]] = node_results

        # Check critical settings
        issues = []

        # Hostname should match
        issues << '主机名不匹配' unless node_results[:hostname][:success] && node_results[:hostname][:output] == node[:name]

        # Swap should still be disabled
        unless node_results[:swap_status][:success] && node_results[:swap_status][:output].to_i <= 1
          issues << 'Swap 未禁用'
        end

        # Kernel modules should be loaded
        unless node_results[:kernel_modules][:success] && node_results[:kernel_modules][:output].to_i >= 2
          issues << '内核模块未加载'
        end

        # Transparent huge pages should be disabled
        unless node_results[:transparent_hugepage][:success] &&
               node_results[:transparent_hugepage][:output].include?('[never]')
          issues << '透明大页未禁用'
        end

        # Timezone should be set to Asia/Hong_Kong
        unless node_results[:timezone][:success] &&
               node_results[:timezone][:output].include?('Asia/Hong_Kong')
          issues << '时区未设置为香港时区'
        end

        if issues.empty?
          @logger.success("节点 #{node[:name]} 重启后验证通过")
        else
          @logger.warn("节点 #{node[:name]} 重启后发现问题: #{issues.join(', ')}")
        end
      end

      @logger.info('重启后验证完成')
    end

    # Class methods for easy access
    class << self
      # Run bootstrap for all nodes in configuration
      #
      # @param config_file [String] Path to configuration file
      # @param reboot [Boolean] Whether to reboot nodes after initialization
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if all nodes bootstrapped successfully
      def run(config_file = 'config.yml', reboot: true, logger: nil)
        bootstrap = new(config_file, logger: logger)
        bootstrap.run(reboot: reboot)
      end

      # Bootstrap a specific node
      #
      # @param node_name [String] Name of the node to bootstrap
      # @param config_file [String] Path to configuration file
      # @param reboot [Boolean] Whether to reboot the node after initialization
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if node bootstrapped successfully
      def bootstrap_node(node_name, config_file = 'config.yml', reboot: true, logger: nil)
        bootstrap = new(config_file, logger: logger)
        bootstrap.load_configuration

        nodes = bootstrap.extract_all_nodes
        target_node = nodes.find { |node| node[:name] == node_name }

        unless target_node
          bootstrap.logger.error("节点 '#{node_name}' 在配置文件中未找到")
          return false
        end

        bootstrap.logger.deploy("🚀 开始初始化节点 #{node_name}")
        result = bootstrap.bootstrap_node(target_node)

        unless result
          bootstrap.logger.error("❌ 节点 #{node_name} 初始化失败")
          return false
        end

        bootstrap.logger.success("✅ 节点 #{node_name} 初始化完成")

        # Reboot single node if requested
        if reboot
          bootstrap.logger.info("📋 重启节点 #{node_name}")

          if bootstrap.reboot_all_nodes([target_node])
            bootstrap.logger.success("🎉 节点 #{node_name} 重启完成！")
            true
          else
            bootstrap.logger.error("❌ 节点 #{node_name} 重启失败")
            false
          end
        else
          bootstrap.logger.info('💡 建议手动重启节点以确保优化配置生效: sudo reboot')
          true
        end
      end
    end
  end
end

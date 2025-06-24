# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT


# frozen_string_literal: true

require 'yaml'
require 'fileutils'
require 'net/ssh'
require 'net/scp'
require 'logger'
require 'stringio'

class Deploy
  def initialize(config_file= 'config.yml')
    @config = YAML.load_file(config_file)
    @token = @config['token']
    @lb_ip = @config['loadbalancer_ip']
    @nodes = @config['nodes']
    @logger = Logger.new('deploy.log')

    # 按角色分组节点
    @server_nodes = @nodes.select { |node| node['role'] == 'server' }
    @agent_nodes = @nodes.select { |node| node['role'] == 'agent' }
    @lb_nodes = @nodes.select { |node| node['role'] == 'lb' }
  end

  def run
    log('🚀 开始 RKE2 集群部署')
    log("服务器节点: #{@server_nodes.size} 个")
    log("工作节点: #{@agent_nodes.size} 个")
    log("负载均衡节点: #{@lb_nodes.size} 个")

    # 0. 首先进行所有节点的初始化和性能优化
    initialize_all_nodes

    # 1. 部署负载均衡节点
    deploy_lb_nodes

    # 2. 部署第一个服务器节点
    deploy_first_server

    # 3. 部署其他服务器节点
    deploy_additional_servers

    # 4. 部署工作节点
    deploy_agent_nodes

    # 5. 配置 Ingress Controller 为 DaemonSet 模式
    configure_ingress_daemonset

    log('🎉 RKE2 集群部署完成!')
  end

  def log(msg)
    puts msg
    @logger.info(msg)
  end

  def initialize_all_nodes
    log('🔧 开始所有节点的初始化和性能优化...')

    all_nodes = @server_nodes + @agent_nodes + @lb_nodes
    log("需要初始化的节点总数: #{all_nodes.size}")

    all_nodes.each do |node|
      initialize_node(node)
    end

    log('✅ 所有节点初始化完成!')
  end

  def initialize_node(node)
    log("🔧 初始化节点 #{node['name']} (#{node['ip']})")

    begin
      Net::SSH.start(node['ip'], node['ssh_user'], timeout: 30) do |ssh|
        log("📤 上传初始化脚本到 #{node['name']}...")

        # 生成初始化脚本
        init_script = generate_init_script(node)
        ssh.scp.upload!(StringIO.new(init_script), '/tmp/node_init.sh')
        ssh.exec!('chmod +x /tmp/node_init.sh')

        log("⚙️  在 #{node['name']} 上执行初始化...")
        output = ssh.exec!('sudo bash /tmp/node_init.sh 2>&1')
        log("📋 #{node['name']} 初始化输出:")
        log(output)

        # 清理临时文件
        ssh.exec!('rm -f /tmp/node_init.sh')

        log("✅ #{node['name']} 初始化完成")
      end
    rescue StandardError => e
      log("❌ #{node['name']} 初始化失败: #{e.message}")
      @logger.error("#{node['name']} initialization failed: #{e.message}")
    end
  end

  def generate_init_script(node)
    <<~SH
            #!/bin/bash
            set -e
            echo "🔧 开始初始化节点 #{node['name']}..."

            # 更新系统信息
            echo "📊 系统信息:"
            echo "  主机名: $(hostname)"
            echo "  系统版本: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
            echo "  内核版本: $(uname -r)"
            echo "  CPU 核心数: $(nproc)"
            echo "  内存大小: $(free -h | grep Mem | awk '{print $2}')"
            echo "  磁盘空间: $(df -h / | tail -1 | awk '{print $4}' | sed 's/G/ GB/')"

            # 1. 系统时间同步
            echo "🕐 配置时间同步..."

            # 检测并配置时间同步服务
            if systemctl list-unit-files | grep -q "^chrony\.service"; then
              # 使用 chrony.service 而不是 chronyd.service
              systemctl enable chrony
              systemctl restart chrony
              echo "  ✅ chrony 时间同步已启用"
            elif systemctl list-unit-files | grep -q "^chronyd\.service"; then
              # 对于一些系统，chronyd 可能是主服务名
              systemctl enable chronyd 2>/dev/null || systemctl enable chrony
              systemctl restart chronyd 2>/dev/null || systemctl restart chrony
              echo "  ✅ chronyd/chrony 时间同步已启用"
            elif command -v ntpd >/dev/null 2>&1; then
              systemctl enable ntp 2>/dev/null || systemctl enable ntpd
              systemctl restart ntp 2>/dev/null || systemctl restart ntpd
              echo "  ✅ ntp 时间同步已启用"
            else
              # 尝试安装时间同步服务
              echo "  📦 安装时间同步服务..."
              if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y chrony >/dev/null 2>&1
                systemctl enable chrony >/dev/null 2>&1
                systemctl start chrony >/dev/null 2>&1
                echo "  ✅ chrony 已安装并启用"
              elif command -v yum >/dev/null 2>&1; then
                yum install -y chrony >/dev/null 2>&1
                systemctl enable chronyd >/dev/null 2>&1
                systemctl start chronyd >/dev/null 2>&1
                echo "  ✅ chrony 已安装并启用"
              elif command -v dnf >/dev/null 2>&1; then
                dnf install -y chrony >/dev/null 2>&1
                systemctl enable chronyd >/dev/null 2>&1
                systemctl start chronyd >/dev/null 2>&1
                echo "  ✅ chrony 已安装并启用"
              else
                echo "  ⚠️  无法安装时间同步服务，请手动配置"
              fi
            fi

            # 验证时间同步状态
            if systemctl is-active chrony >/dev/null 2>&1; then
              echo "  📊 chrony 状态: $(systemctl is-active chrony)"
            elif systemctl is-active chronyd >/dev/null 2>&1; then
              echo "  📊 chronyd 状态: $(systemctl is-active chronyd)"
            elif systemctl is-active ntp >/dev/null 2>&1; then
              echo "  📊 ntp 状态: $(systemctl is-active ntp)"
            elif systemctl is-active ntpd >/dev/null 2>&1; then
              echo "  📊 ntpd 状态: $(systemctl is-active ntpd)"
            fi

            # 2. 禁用 swap
            echo "💾 禁用 swap..."
            swapoff -a
            sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab
            echo "  ✅ swap 已禁用"

            # 3. 内核模块加载
            echo "🔧 配置内核模块..."
            cat > /etc/modules-load.d/k8s.conf << 'EOF'
      overlay
      br_netfilter
      ip_vs
      ip_vs_rr
      ip_vs_wrr
      ip_vs_sh
      nf_conntrack
      EOF

            # 加载模块
            modprobe overlay 2>/dev/null || true
            modprobe br_netfilter 2>/dev/null || true
            modprobe ip_vs 2>/dev/null || true
            modprobe ip_vs_rr 2>/dev/null || true
            modprobe ip_vs_wrr 2>/dev/null || true
            modprobe ip_vs_sh 2>/dev/null || true
            modprobe nf_conntrack 2>/dev/null || true
            echo "  ✅ 内核模块已加载"

            # 4. 系统参数优化
            echo "⚡ 配置系统参数优化..."
            cat > /etc/sysctl.d/99-k8s.conf << 'EOF'
      # 网络优化
      net.bridge.bridge-nf-call-iptables = 1
      net.bridge.bridge-nf-call-ip6tables = 1
      net.ipv4.ip_forward = 1
      net.ipv4.conf.all.forwarding = 1
      net.ipv6.conf.all.forwarding = 1

      # 连接跟踪优化
      net.netfilter.nf_conntrack_max = 1000000
      net.netfilter.nf_conntrack_tcp_timeout_established = 86400

      # TCP 优化
      net.core.somaxconn = 32768
      net.core.netdev_max_backlog = 16384
      net.core.rmem_default = 262144
      net.core.rmem_max = 16777216
      net.core.wmem_default = 262144
      net.core.wmem_max = 16777216
      net.ipv4.tcp_rmem = 4096 65536 16777216
      net.ipv4.tcp_wmem = 4096 65536 16777216
      net.ipv4.tcp_max_syn_backlog = 8192
      net.ipv4.tcp_slow_start_after_idle = 0

      # 内存和进程优化
      vm.swappiness = 0
      vm.overcommit_memory = 1
      vm.panic_on_oom = 0
      vm.max_map_count = 262144
      kernel.panic = 10
      kernel.panic_on_oops = 1
      kernel.pid_max = 4194304

      # 文件系统优化
      fs.file-max = 2097152
      fs.inotify.max_user_instances = 8192
      fs.inotify.max_user_watches = 524288
      fs.may_detach_mounts = 1

      # 安全优化
      kernel.dmesg_restrict = 1
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.send_redirects = 0
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv4.conf.all.accept_source_route = 0
      net.ipv4.conf.default.accept_source_route = 0
      EOF

            # 应用系统参数
            sysctl --system >/dev/null 2>&1
            echo "  ✅ 系统参数优化已应用"

            # 5. 系统限制优化
            echo "📈 配置系统限制..."
            cat > /etc/security/limits.d/99-k8s.conf << 'EOF'
      * soft nofile 1048576
      * hard nofile 1048576
      * soft nproc 1048576
      * hard nproc 1048576
      * soft core unlimited
      * hard core unlimited
      * soft memlock unlimited
      * hard memlock unlimited
      root soft nofile 1048576
      root hard nofile 1048576
      root soft nproc 1048576
      root hard nproc 1048576
      EOF
            echo "  ✅ 系统限制已优化"

            # 6. 防火墙配置
            echo "🔥 配置防火墙..."
            if systemctl is-active firewalld >/dev/null 2>&1; then
              echo "  禁用 firewalld (使用 iptables)..."
              systemctl stop firewalld
              systemctl disable firewalld
            fi

            if systemctl is-active ufw >/dev/null 2>&1; then
              echo "  禁用 ufw (使用 iptables)..."
              systemctl stop ufw
              systemctl disable ufw
            fi
            echo "  ✅ 防火墙已配置"

            # 7. 安装必要的系统工具
            echo "📦 安装系统工具..."
            if command -v apt-get >/dev/null 2>&1; then
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get install -y \\
                curl wget git vim htop iotop nethogs \\
                net-tools dnsutils ipset conntrack \\
                socat jq unzip tar gzip \\
                ca-certificates gnupg lsb-release \\
                apt-transport-https software-properties-common \\
                >/dev/null 2>&1
            elif command -v yum >/dev/null 2>&1; then
              yum install -y \\
                curl wget git vim htop iotop nethogs \\
                net-tools bind-utils ipset conntrack-tools \\
                socat jq unzip tar gzip \\
                ca-certificates gnupg \\
                yum-utils device-mapper-persistent-data lvm2 \\
                >/dev/null 2>&1
            fi
            echo "  ✅ 系统工具安装完成"

            # 8. 磁盘性能优化
            echo "💿 优化磁盘性能..."
            # 设置磁盘调度器为 deadline 或 noop
            for disk in $(lsblk -d -n -o NAME | grep -E '^(sd|vd|nvme)'); do
              if [ -f "/sys/block/$disk/queue/scheduler" ]; then
                if grep -q "\\[mq-deadline\\]" "/sys/block/$disk/queue/scheduler"; then
                  echo "  磁盘 $disk 已使用 mq-deadline 调度器"
                elif grep -q "deadline" "/sys/block/$disk/queue/scheduler"; then
                  echo deadline > "/sys/block/$disk/queue/scheduler" 2>/dev/null || true
                  echo "  磁盘 $disk 设置为 deadline 调度器"
                elif grep -q "noop" "/sys/block/$disk/queue/scheduler"; then
                  echo noop > "/sys/block/$disk/queue/scheduler" 2>/dev/null || true
                  echo "  磁盘 $disk 设置为 noop 调度器"
                fi
              fi
            done
            echo "  ✅ 磁盘调度器已优化"

            # 9. 设置主机名
            echo "🏷️  设置主机名..."
            if [ "$(hostname)" != "#{node['name']}" ]; then
              hostnamectl set-hostname #{node['name']} 2>/dev/null || hostname #{node['name']}
              echo "  ✅ 主机名已设置为 #{node['name']}"
            else
              echo "  ✅ 主机名已正确设置"
            fi

            # 10. 配置 DNS 解析优化
            echo "🌐 优化 DNS 配置..."
            # 备份原始 resolv.conf
            if [ ! -f /etc/resolv.conf.backup ]; then
              cp /etc/resolv.conf /etc/resolv.conf.backup
            fi

            # 添加高性能 DNS 服务器
            cat > /etc/resolv.conf.new << 'EOF'
      # Optimized DNS configuration for Kubernetes
      nameserver 8.8.8.8
      nameserver 8.8.4.4
      nameserver 1.1.1.1
      nameserver 1.0.0.1
      options timeout:2 attempts:3 rotate single-request-reopen
      EOF

            # 如果原来有自定义 DNS，保留它们
            if grep -v "^#" /etc/resolv.conf.backup | grep -q "nameserver"; then
              grep "nameserver" /etc/resolv.conf.backup | head -2 > /tmp/custom_dns
              cat /tmp/custom_dns /etc/resolv.conf.new > /etc/resolv.conf.tmp
              mv /etc/resolv.conf.tmp /etc/resolv.conf
              rm -f /tmp/custom_dns
            else
              mv /etc/resolv.conf.new /etc/resolv.conf
            fi
            echo "  ✅ DNS 配置已优化"

            # 11. 内存优化
            echo "🧠 配置内存优化..."
            # 配置内存回收策略
            echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true

            # 如果是虚拟机，禁用透明大页
            if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
              echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
              echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
              echo "  ✅ 透明大页已禁用"
            fi

            # 配置开机自动禁用透明大页
            cat > /etc/systemd/system/disable-thp.service << 'EOF'
      [Unit]
      Description=Disable Transparent Huge Pages (THP)
      DefaultDependencies=no
      After=sysinit.target local-fs.target
      Before=basic.target

      [Service]
      Type=oneshot
      ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag'

      [Install]
      WantedBy=basic.target
      EOF
            systemctl enable disable-thp.service >/dev/null 2>&1 || true
            echo "  ✅ 内存优化已配置"

            # 12. 系统状态检查
            echo "🔍 系统状态检查..."
            echo "  CPU 使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
            echo "  内存使用率: $(free | grep Mem | awk '{printf("%.1f%%\\n", $3/$2 * 100.0)}')"
            echo "  磁盘使用率: $(df -h / | tail -1 | awk '{print $5}')"
            echo "  系统负载: $(uptime | awk -F'load average:' '{print $2}')"
            echo "  打开文件数限制: $(ulimit -n)"
            echo "  进程数限制: $(ulimit -u)"

            # 13. 重启必要的服务
            echo "🔄 重启系统服务..."
            systemctl daemon-reload

            # 重启网络相关服务（如果存在）
            if systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
              systemctl restart systemd-networkd
            fi

            if systemctl is-enabled NetworkManager >/dev/null 2>&1; then
              systemctl restart NetworkManager
            fi
            echo "  ✅ 系统服务已重启"

            echo ""
            echo "🎉 节点 #{node['name']} 初始化完成！"
            echo "📈 性能优化摘要:"
            echo "  - ✅ 时间同步已配置"
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
            echo ""
            echo "💡 建议: 在继续部署前重启节点以确保所有优化生效"
            echo "   重启命令: sudo reboot"
            echo ""
    SH
  end

  def deploy_lb_nodes
    return if @lb_nodes.empty?

    log('📋 部署负载均衡节点...')
    @lb_nodes.each do |node|
      log("🔧 配置负载均衡器 #{node['name']} (#{node['ip']})")
      write_nginx_config(node)
      write_lb_install_script(node)
      deploy_to_node(node)
    end
  end

  def deploy_first_server
    return if @server_nodes.empty?

    first_server = @server_nodes.first
    log("🔧 部署第一个服务器节点 #{first_server['name']}")
    write_config_file(first_server, true)
    write_install_script(first_server)
    deploy_to_node(first_server)

    # 等待第一个服务器节点启动
    wait_for_server_ready(first_server)
  end

  def deploy_additional_servers
    additional_servers = @server_nodes[1..] || []
    return if additional_servers.empty?

    log('🔧 部署其他服务器节点...')
    additional_servers.each do |node|
      log("🔧 配置服务器节点 #{node['name']}")
      write_config_file(node, false)
      write_install_script(node)
      deploy_to_node(node)
    end
  end

  def deploy_agent_nodes
    return if @agent_nodes.empty?

    log('🔧 部署工作节点...')
    @agent_nodes.each do |node|
      log("🔧 配置工作节点 #{node['name']}")
      write_config_file(node, false)
      write_install_script(node)
      deploy_to_node(node)
    end
  end

  def write_nginx_config(node)
    # 获取所有服务器节点的IP地址
    server_ips = @server_nodes.map { |n| n['ip'] }

    haproxy_config = <<~HAPROXY
      global
        daemon
        log stdout local0
        chroot /var/lib/haproxy
        stats socket /run/haproxy/admin.sock mode 660 level admin
        stats timeout 30s
        user haproxy
        group haproxy

      defaults
        mode tcp
        log global
        option tcplog
        option dontlognull
        option log-health-checks
        timeout connect 5000ms
        timeout client 50000ms
        timeout server 50000ms

      # Kubernetes API Server
      frontend kubernetes-api
        bind *:6443
        mode tcp
        default_backend kubernetes-api-backend

      backend kubernetes-api-backend
        mode tcp
        balance roundrobin
        option tcp-check
        #{server_ips.map { |ip| "server master-#{ip.gsub('.', '-')} #{ip}:6443 check" }.join("\n  ")}

      # RKE2 Registration Server
      frontend rke2-registration
        bind *:9345
        mode tcp
        default_backend rke2-registration-backend

      backend rke2-registration-backend
        mode tcp
        balance roundrobin
        option tcp-check
        #{server_ips.map { |ip| "server master-#{ip.gsub('.', '-')} #{ip}:9345 check" }.join("\n  ")}

      # Stats interface
      frontend stats
        bind *:8404
        mode http
        stats enable
        stats uri /stats
        stats refresh 30s
        stats admin if TRUE
    HAPROXY

    dir = "output/#{node['name']}"
    FileUtils.mkdir_p(dir)
    File.write("#{dir}/haproxy.cfg", haproxy_config)
  end

  def write_lb_install_script(node)
    script = <<~SH
      #!/bin/bash
      set -e
      echo "🚀 Installing HAProxy Load Balancer on #{node['name']}"

      # 安装 HAProxy
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y haproxy
      elif command -v yum >/dev/null 2>&1; then
        yum install -y haproxy
      else
        echo "❌ 不支持的包管理器"
        exit 1
      fi

      # 备份原始配置
      cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup

      # 复制我们的配置文件
      cp /tmp/haproxy.cfg /etc/haproxy/haproxy.cfg

      # 测试配置
      haproxy -f /etc/haproxy/haproxy.cfg -c

      # 启用并启动 HAProxy
      systemctl enable haproxy
      systemctl restart haproxy

      # 检查 HAProxy 状态
      systemctl status haproxy --no-pager

      # 显示监听端口
      echo "🔍 检查监听端口:"
      ss -tlnp | grep -E ':6443|:9345|:8404'

      echo "✅ HAProxy 负载均衡器配置完成"
      echo "📊 统计页面: http://#{node['ip']}:8404/stats"
    SH

    File.write("output/#{node['name']}/install.sh", script)
    FileUtils.chmod('+x', "output/#{node['name']}/install.sh")
  end

  def write_config_file(node, is_first_server = false)
    content = case node['role']
              when 'server'
                if is_first_server
                  <<~YAML
                    token: #{@token}
                    node-name: #{node['name']}
                    bind-address: 0.0.0.0
                    advertise-address: #{node['ip']}
                    tls-san:
                      - "0.0.0.0"
                      - "#{@lb_ip}"
                      - "#{node['ip']}"
                    cni: canal
                    write-kubeconfig-mode: "0644"
                    cluster-init: true
                  YAML
                else
                  <<~YAML
                    server: https://#{@lb_ip}:9345
                    token: #{@token}
                    node-name: #{node['name']}
                    bind-address: 0.0.0.0
                    advertise-address: #{node['ip']}
                    tls-san:
                      - "0.0.0.0"
                      - "#{@lb_ip}"
                      - "#{node['ip']}"
                    cni: canal
                    write-kubeconfig-mode: "0644"
                  YAML
                end
              when 'agent'
                <<~YAML
                  server: https://#{@lb_ip}:9345
                  token: #{@token}
                  node-name: #{node['name']}
                YAML
              end

    return unless content

    dir = "output/#{node['name']}"
    FileUtils.mkdir_p(dir)
    File.write("#{dir}/config.yaml", content)
  end

  def write_install_script(node)
    role = node['role']
    service = role == 'server' ? 'rke2-server' : 'rke2-agent'

    script = <<~SH
      #!/bin/bash
      set -e
      echo "🚀 Installing RKE2 (#{role}) on #{node['name']}"

      # 下载并安装 RKE2
      curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE=#{role} sh -

      # 创建配置目录
      mkdir -p /etc/rancher/rke2

      # 复制配置文件
      cp /tmp/config.yaml /etc/rancher/rke2/config.yaml

      # 设置正确的权限
      chmod 600 /etc/rancher/rke2/config.yaml

      # 启用服务
      systemctl enable #{service}

      # 启动服务
      systemctl restart #{service}

      echo "✅ RKE2 #{role} 安装完成"

      # 显示服务状态
      systemctl status #{service} --no-pager
    SH

    # 如果是 server 节点，添加 kubectl 配置
    if role == 'server'
      script += <<~SH

                echo "🔧 配置 kubectl for root 用户..."

                # 等待 kubeconfig 文件生成 (最多等待 60 秒)
                echo "⏳ 等待 kubeconfig 文件生成..."
                for i in {1..12}; do
                  if [ -f /etc/rancher/rke2/rke2.yaml ]; then
                    break
                  fi
                  echo "  等待中... ($i/12)"
                  sleep 5
                done

                if [ ! -f /etc/rancher/rke2/rke2.yaml ]; then
                  echo "❌ kubeconfig 文件未找到，请稍后手动配置"
                  exit 1
                fi

                # 创建 kubectl 软链接到系统 PATH
                echo "🔗 创建 kubectl 软链接..."
                ln -sf /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
                chmod +x /usr/local/bin/kubectl

                # 为 root 用户设置 kubeconfig
                echo "📝 为 root 用户配置 kubeconfig..."
                mkdir -p /root/.kube
                cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
                chmod 600 /root/.kube/config
                chown root:root /root/.kube/config

                # 设置环境变量到 root 的 bashrc
                echo "🔧 配置环境变量..."
                if ! grep -q "KUBECONFIG" /root/.bashrc; then
                  echo "# RKE2 kubectl configuration" >> /root/.bashrc
                  echo "export KUBECONFIG=/root/.kube/config" >> /root/.bashrc
                  echo "export PATH=/var/lib/rancher/rke2/bin:$PATH" >> /root/.bashrc
                  echo "alias k=kubectl" >> /root/.bashrc
                fi

                # 设置环境变量到 root 的 profile
                if ! grep -q "KUBECONFIG" /root/.profile; then
                  echo "# RKE2 kubectl configuration" >> /root/.profile
                  echo "export KUBECONFIG=/root/.kube/config" >> /root/.profile
                  echo "export PATH=/var/lib/rancher/rke2/bin:$PATH" >> /root/.profile
                fi

                # 测试 kubectl 配置
                echo "🧪 测试 kubectl 配置..."
                export KUBECONFIG=/root/.kube/config
                export PATH=/var/lib/rancher/rke2/bin:$PATH

                # 等待 API 服务器就绪
                echo "⏳ 等待 Kubernetes API 服务器就绪..."
                for i in {1..24}; do
                  if kubectl cluster-info >/dev/null 2>&1; then
                    echo "✅ API 服务器已就绪"
                    break
                  fi
                  echo "  等待 API 服务器... ($i/24)"
                  sleep 5
                done

                # 验证 kubectl 功能
                echo "🔍 验证 kubectl 功能..."
                if kubectl get nodes >/dev/null 2>&1; then
                  echo "✅ kubectl 配置成功！"
                  echo "📊 当前集群节点:"
                  kubectl get nodes
                else
                  echo "⚠️  kubectl 配置可能需要更多时间生效"
                fi

                echo ""
                echo "🎉 kubectl 配置完成！"
                echo "💡 提示: 重新登录 root 用户后，可以直接使用以下命令:"
                echo "   kubectl get nodes"
                echo "   k get pods --all-namespaces"
                echo ""

                # 安装 k9s
                echo "📦 安装 k9s..."
                K9S_VERSION=$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\\1/')
                echo "  下载 k9s $K9S_VERSION..."

                # 检测系统架构
                ARCH=$(uname -m)
                case $ARCH in
                  x86_64) K9S_ARCH="amd64" ;;
                  aarch64) K9S_ARCH="arm64" ;;
                  *) K9S_ARCH="amd64" ;;
                esac

                curl -sL "https://github.com/derailed/k9s/releases/download/$K9S_VERSION/k9s_Linux_$K9S_ARCH.tar.gz" -o /tmp/k9s.tar.gz
                tar -xzf /tmp/k9s.tar.gz -C /tmp
                mv /tmp/k9s /usr/local/bin/k9s
                chmod +x /usr/local/bin/k9s
                rm -f /tmp/k9s.tar.gz /tmp/LICENSE /tmp/README.md

                # 验证 k9s 安装
                if k9s version >/dev/null 2>&1; then
                  echo "  ✅ k9s 安装成功: $(k9s version --short)"
                else
                  echo "  ⚠️  k9s 安装可能有问题"
                fi

                # 安装 helm
                echo "📦 安装 helm..."
                curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
                chmod 700 /tmp/get_helm.sh
                HELM_INSTALL_DIR="/usr/local/bin" /tmp/get_helm.sh --no-sudo >/dev/null 2>&1
                rm -f /tmp/get_helm.sh

                # 验证 helm 安装
                if helm version >/dev/null 2>&1; then
                  echo "  ✅ helm 安装成功: $(helm version --short)"
                else
                  echo "  ⚠️  helm 安装可能有问题"
                fi

                # 初始化 helm
                echo "🔧 初始化 helm..."
                export KUBECONFIG=/root/.kube/config
                helm repo add stable https://charts.helm.sh/stable >/dev/null 2>&1 || true
                helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || true
                helm repo update >/dev/null 2>&1 || true
                echo "  ✅ helm 仓库初始化完成"

                # 创建 k9s 配置目录
                echo "🔧 配置 k9s..."
                mkdir -p /root/.config/k9s

                # 创建 k9s 基础配置
                cat > /root/.config/k9s/config.yml << 'EOF'
        k9s:
          liveViewAutoRefresh: true
          refreshRate: 2
          maxConnRetry: 5
          readOnly: false
          noExitOnCtrlC: false
          ui:
            enableMouse: true
            headless: false
            logoless: false
            crumbsless: false
            reactive: false
            noIcons: false
          skipLatestRevCheck: false
          disablePodCounting: false
          shellPod:
            image: busybox:1.35.0
            namespace: default
            limits:
              cpu: 100m
              memory: 100Mi
          imageScanner:
            enable: false
          logger:
            tail: 100
            buffer: 5000
            sinceSeconds: -1
            textWrap: false
            showTime: false
        EOF

                echo ""
                echo "🎉 k9s 和 helm 安装完成！"
                echo ""
                echo "💡 可用工具："
                echo "   kubectl get nodes          # Kubernetes 命令行工具"
                echo "   k get pods --all-namespaces # kubectl 别名"
                echo "   k9s                        # 终端 UI 集群管理工具"
                echo "   helm list                  # Kubernetes 包管理器"
                echo ""
                echo "🚀 k9s 使用提示："
                echo "   - 按 ':' 进入命令模式"
                echo "   - 输入资源名称快速跳转 (pods, svc, deploy 等)"
                echo "   - 按 '?' 查看帮助"
                echo "   - 按 'Ctrl+C' 退出"
                echo ""
      SH
    end

    File.write("output/#{node['name']}/install.sh", script)
    FileUtils.chmod('+x', "output/#{node['name']}/install.sh")
  end

  def wait_for_server_ready(node)
    log("⏳ 等待服务器节点 #{node['name']} 就绪...")

    max_attempts = 30
    attempt = 0

    while attempt < max_attempts
      begin
        Net::SSH.start(node['ip'], node['ssh_user'], timeout: 10) do |ssh|
          # 检查服务状态
          status = ssh.exec!('systemctl is-active rke2-server').strip
          if status == 'active'
            # 进一步检查服务是否真正就绪
            ready_status = check_cluster_readiness(ssh, node)
            if ready_status[:ready]
              log("✅ 服务器节点 #{node['name']} 已完全就绪")
              return true
            else
              log("⏳ 服务运行中但组件仍在初始化... #{ready_status[:status]}")
            end
          else
            log("⏳ 服务状态: #{status}")
          end
        end
      rescue StandardError => e
        log("⏳ 尝试 #{attempt + 1}/#{max_attempts}: #{e.message}")
      end

      attempt += 1
      sleep(30)
    end

    log("⚠️  服务器节点 #{node['name']} 可能需要更多时间启动")
    false
  end

  # 检查集群就绪状态的新方法
  def check_cluster_readiness(ssh, _node)
    # 检查 containerd 进程是否运行
    containerd_running = ssh.exec!('pgrep -f "containerd.*rke2" >/dev/null 2>&1 && echo "running" || echo "not_running"').strip

    # 检查 kubelet 进程是否运行
    kubelet_running = ssh.exec!('pgrep -f "kubelet.*rke2" >/dev/null 2>&1 && echo "running" || echo "not_running"').strip

    # 检查 kubectl 是否可用并能访问 API
    kubectl_check = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl get nodes 2>/dev/null | wc -l').strip.to_i

    # 检查 etcd 是否健康
    etcd_check = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl get nodes --selector node-role.kubernetes.io/etcd 2>/dev/null | grep -c Ready || echo 0').strip.to_i

    # 检查 API 服务器是否响应
    api_server_check = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && timeout 5 /var/lib/rancher/rke2/bin/kubectl cluster-info >/dev/null 2>&1 && echo "responding" || echo "not_responding"').strip

    if containerd_running == 'running' && kubelet_running == 'running' && kubectl_check > 1 && etcd_check.positive? && api_server_check == 'responding'
      return { ready: true, status: 'All components operational' }
    end

    status_msg = "containerd:#{containerd_running}, kubelet:#{kubelet_running}, kubectl_nodes:#{kubectl_check}, etcd_ready:#{etcd_check}, api_server:#{api_server_check}"
    { ready: false, status: status_msg }
  rescue StandardError => e
    { ready: false, status: "Check failed: #{e.message}" }
  end

  # 新的诊断方法
  def diagnose_cluster_status
    log('🔍 诊断集群状态...')

    @server_nodes.each do |node|
      log("\n📊 检查节点: #{node['name']} (#{node['ip']})")

      begin
        Net::SSH.start(node['ip'], node['ssh_user'], timeout: 15) do |ssh|
          # RKE2 服务状态
          log('🔧 RKE2 服务状态:')
          rke2_status = ssh.exec!("systemctl is-active rke2-server 2>/dev/null || echo 'not-found'").strip
          rke2_state = ssh.exec!("systemctl is-enabled rke2-server 2>/dev/null || echo 'not-found'").strip
          log("  rke2-server: #{rke2_status} (#{rke2_state})")

          # 检查关键进程状态（RKE2 中 containerd 和 kubelet 是子进程）
          log("\n🔄 关键进程状态:")
          containerd_running = ssh.exec!('pgrep -f "containerd.*rke2" >/dev/null && echo "running" || echo "not_running"').strip
          kubelet_running = ssh.exec!('pgrep -f "kubelet.*rke2" >/dev/null && echo "running" || echo "not_running"').strip
          etcd_running = ssh.exec!('pgrep -f "etcd.*rke2" >/dev/null && echo "running" || echo "not_running"').strip

          log("  containerd: #{containerd_running}")
          log("  kubelet: #{kubelet_running}")
          log("  etcd: #{etcd_running}")

          # 检查进程详情
          log("\n🔍 进程详情:")
          process_count = ssh.exec!('ps aux | grep -E "(rke2|containerd|kubelet|etcd)" | grep -v grep | wc -l').strip
          log("  RKE2 相关进程总数: #{process_count}")

          # 检查最近的 journal 日志
          log("\n📋 最近的 RKE2 日志 (最后5行):")
          recent_logs = ssh.exec!('journalctl -u rke2-server --no-pager -n 5 --since "2 minutes ago" 2>/dev/null || echo "无法获取日志"')
          log(recent_logs)

          # 检查网络和端口
          log("\n🌐 网络状态:")
          api_port = ssh.exec!('ss -tlnp | grep ":6443" | wc -l').strip
          reg_port = ssh.exec!('ss -tlnp | grep ":9345" | wc -l').strip
          kubelet_port = ssh.exec!('ss -tlnp | grep ":10250" | wc -l').strip

          log("  API 服务器端口 (6443): #{api_port > '0' ? '✅ 监听中' : '❌ 未监听'}")
          log("  注册服务端口 (9345): #{reg_port > '0' ? '✅ 监听中' : '❌ 未监听'}")
          log("  Kubelet 端口 (10250): #{kubelet_port > '0' ? '✅ 监听中' : '❌ 未监听'}")

          # 检查集群就绪状态
          log("\n🎯 集群就绪性检查:")
          ready_status = check_cluster_readiness(ssh, node)
          log("  集群状态: #{ready_status[:ready] ? '✅ 就绪' : '⏳ 未就绪'}")
          log("  详细信息: #{ready_status[:status]}")

          # kubectl 功能测试
          log("\n🧪 kubectl 功能测试:")
          kubectl_test = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && timeout 10 /var/lib/rancher/rke2/bin/kubectl get nodes --no-headers 2>/dev/null | wc -l').strip
          if kubectl_test.to_i > 0
            log("  ✅ kubectl 正常工作，发现 #{kubectl_test} 个节点")
          else
            log('  ❌ kubectl 无法正常工作')
          end
        end
      rescue StandardError => e
        log("❌ 无法连接到 #{node['name']}: #{e.message}")
      end
    end
  end

  def configure_ingress_daemonset
    log('🔧 配置 Ingress Controller 为 DaemonSet 模式...')

    return if @server_nodes.empty?

    first_server = @server_nodes.first
    log("📝 在 #{first_server['name']} 上配置 Ingress DaemonSet...")

    begin
      Net::SSH.start(first_server['ip'], first_server['ssh_user'], timeout: 30) do |ssh|
        # 等待集群就绪
        log('⏳ 等待集群 API 完全就绪...')
        wait_for_api_ready(ssh)

        # 生成 Ingress DaemonSet 配置
        ingress_config = generate_ingress_daemonset_manifest
        ssh.scp.upload!(StringIO.new(ingress_config), '/tmp/nginx-ingress-daemonset.yaml')

        log('🚀 部署 Nginx Ingress Controller (DaemonSet 模式)...')

        # 应用配置
        output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl apply -f /tmp/nginx-ingress-daemonset.yaml 2>&1')
        log('📋 Ingress DaemonSet 部署输出:')
        log(output)

        # 等待 DaemonSet 就绪
        log('⏳ 等待 Ingress DaemonSet 就绪...')
        ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx rollout status daemonset/nginx-ingress-controller --timeout=300s')

        # 验证部署状态
        log('🔍 验证 Ingress Controller 状态...')
        status_output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx get daemonset,pods -o wide')
        log('📊 Ingress Controller 状态:')
        log(status_output)

        # 清理临时文件
        ssh.exec!('rm -f /tmp/nginx-ingress-daemonset.yaml')

        log('✅ Ingress Controller DaemonSet 配置完成!')
      end
    rescue StandardError => e
      log("❌ Ingress DaemonSet 配置失败: #{e.message}")
      @logger.error("Ingress DaemonSet configuration failed: #{e.message}")
    end
  end

  def wait_for_api_ready(ssh)
    max_attempts = 20
    attempt = 0

    while attempt < max_attempts
      begin
        result = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && timeout 10 /var/lib/rancher/rke2/bin/kubectl get nodes >/dev/null 2>&1 && echo "ready"').strip
        if result == 'ready'
          log('✅ API 服务器已就绪')
          return true
        end
      rescue StandardError => e
        log("⏳ 等待 API 就绪... (#{attempt + 1}/#{max_attempts}): #{e.message}")
      end

      attempt += 1
      sleep(15)
    end

    log('⚠️ API 服务器等待超时，但继续配置...')
    false
  end

  def generate_ingress_daemonset_manifest
    <<~YAML
      apiVersion: v1
      kind: Namespace
      metadata:
        name: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/instance: ingress-nginx
      ---
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: nginx-configuration
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      data:
        worker-processes: "auto"
        worker-connections: "16384"
        enable-real-ip: "true"
        use-gzip: "true"
        gzip-level: "6"
      ---
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: nginx-ingress-serviceaccount
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRole
      metadata:
        name: nginx-ingress-clusterrole
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      rules:
        - apiGroups: [""]
          resources: ["configmaps", "endpoints", "nodes", "pods", "secrets", "namespaces"]
          verbs: ["list", "watch", "get"]
        - apiGroups: [""]
          resources: ["services"]
          verbs: ["get", "list", "watch"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingresses"]
          verbs: ["get", "list", "watch"]
        - apiGroups: [""]
          resources: ["events"]
          verbs: ["create", "patch"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingresses/status"]
          verbs: ["update"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingressclasses"]
          verbs: ["get", "list", "watch"]
        - apiGroups: ["coordination.k8s.io"]
          resources: ["leases"]
          verbs: ["list", "watch", "get", "update", "create"]
        - apiGroups: ["discovery.k8s.io"]
          resources: ["endpointslices"]
          verbs: ["list", "watch", "get"]
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: Role
      metadata:
        name: nginx-ingress-role
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      rules:
        - apiGroups: [""]
          resources: ["configmaps", "pods", "secrets", "namespaces"]
          verbs: ["get"]
        - apiGroups: [""]
          resources: ["configmaps"]
          resourceNames: ["ingress-controller-leader"]
          verbs: ["get", "update"]
        - apiGroups: [""]
          resources: ["configmaps"]
          verbs: ["create"]
        - apiGroups: ["coordination.k8s.io"]
          resources: ["leases"]
          verbs: ["get", "create", "update"]
        - apiGroups: [""]
          resources: ["endpoints"]
          verbs: ["get"]
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: RoleBinding
      metadata:
        name: nginx-ingress-role-nisa-binding
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      roleRef:
        apiGroup: rbac.authorization.k8s.io
        kind: Role
        name: nginx-ingress-role
      subjects:
        - kind: ServiceAccount
          name: nginx-ingress-serviceaccount
          namespace: ingress-nginx
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRoleBinding
      metadata:
        name: nginx-ingress-clusterrole-nisa-binding
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      roleRef:
        apiGroup: rbac.authorization.k8s.io
        kind: ClusterRole
        name: nginx-ingress-clusterrole
      subjects:
        - kind: ServiceAccount
          name: nginx-ingress-serviceaccount
          namespace: ingress-nginx
      ---
      apiVersion: apps/v1
      kind: DaemonSet
      metadata:
        name: nginx-ingress-controller
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
          app.kubernetes.io/component: controller
      spec:
        selector:
          matchLabels:
            app.kubernetes.io/name: ingress-nginx
            app.kubernetes.io/part-of: ingress-nginx
            app.kubernetes.io/component: controller
        template:
          metadata:
            labels:
              app.kubernetes.io/name: ingress-nginx
              app.kubernetes.io/part-of: ingress-nginx
              app.kubernetes.io/component: controller
            annotations:
              prometheus.io/port: "10254"
              prometheus.io/scrape: "true"
          spec:
            serviceAccountName: nginx-ingress-serviceaccount
            hostNetwork: true
            dnsPolicy: ClusterFirstWithHostNet
            nodeSelector:
              kubernetes.io/os: linux
            tolerations:
            - key: node-role.kubernetes.io/control-plane
              operator: Exists
              effect: NoSchedule
            - key: node-role.kubernetes.io/master
              operator: Exists
              effect: NoSchedule
            containers:
            - name: nginx-ingress-controller
              image: registry.k8s.io/ingress-nginx/controller:v1.8.2
              args:
                - /nginx-ingress-controller
                - --configmap=$(POD_NAMESPACE)/nginx-configuration
                - --ingress-class=nginx
                - --watch-ingress-without-class=true
                - --http-port=80
                - --https-port=443
                - --healthz-port=10254
                - --enable-ssl-passthrough
              securityContext:
                allowPrivilegeEscalation: true
                capabilities:
                  drop: [ALL]
                  add: [NET_BIND_SERVICE]
                runAsUser: 101
                runAsGroup: 82
              env:
                - name: POD_NAME
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.name
                - name: POD_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
              ports:
              - name: http
                containerPort: 80
                hostPort: 80
                protocol: TCP
              - name: https
                containerPort: 443
                hostPort: 443
                protocol: TCP
              - name: webhook
                containerPort: 8443
                protocol: TCP
              - name: metrics
                containerPort: 10254
                protocol: TCP
              livenessProbe:
                httpGet:
                  path: /healthz
                  port: 10254
                  scheme: HTTP
                initialDelaySeconds: 30
                periodSeconds: 10
                timeoutSeconds: 5
                failureThreshold: 3
              readinessProbe:
                httpGet:
                  path: /healthz
                  port: 10254
                  scheme: HTTP
                periodSeconds: 10
                timeoutSeconds: 5
                failureThreshold: 3
              resources:
                requests:
                  cpu: 100m
                  memory: 128Mi
                limits:
                  cpu: 1000m
                  memory: 512Mi
      ---
      apiVersion: networking.k8s.io/v1
      kind: IngressClass
      metadata:
        name: nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      spec:
        controller: k8s.io/ingress-nginx
    YAML
  end

  # 新的状态监控方法
  def monitor_startup_progress(node, max_wait_minutes = 15)
    log("🔄 监控 #{node['name']} 启动进度 (最大等待 #{max_wait_minutes} 分钟)...")

    start_time = Time.now
    last_status = ''

    while (Time.now - start_time) < (max_wait_minutes * 60)
      begin
        Net::SSH.start(node['ip'], node['ssh_user'], timeout: 10) do |ssh|
          # 获取最新的状态消息
          recent_log = ssh.exec!('journalctl -u rke2-server --no-pager -n 1 --since "30 seconds ago" -o cat 2>/dev/null | tail -1').strip

          if recent_log != last_status && !recent_log.empty?
            log("📝 #{Time.now.strftime('%H:%M:%S')}: #{recent_log}")
            last_status = recent_log
          end

          # 检查是否有错误退出
          service_failed = ssh.exec!('systemctl is-failed rke2-server 2>/dev/null').strip
          if service_failed == 'failed'
            log('❌ RKE2 服务失败,检查详细日志:')
            error_logs = ssh.exec!('journalctl -u rke2-server --no-pager -n 20 | tail -10')
            log(error_logs)
            return false
          end

          # 检查是否已就绪
          ready_check = check_cluster_readiness(ssh, node)
          if ready_check[:ready]
            log("✅ #{node['name']} 启动完成!")
            return true
          end
        end
      rescue StandardError => e
        log("⚠️  监控连接问题: #{e.message}")
      end

      sleep(30)
    end

    log('⏰ 监控超时,但这不一定意味着失败')
    false
  end

  def deploy_to_node(node)
    ip = node['ip']
    user = node['ssh_user'] || 'root'
    name = node['name']
    role = node['role']

    log("🔗 连接 #{name} (#{ip}) - #{role}")

    begin
      Net::SSH.start(ip, user, timeout: 30) do |ssh|
        log("📤 上传文件到 #{name}...")
        ssh.exec!('mkdir -p /tmp')

        # 上传配置文件
        if role == 'lb'
          ssh.scp.upload!("output/#{name}/haproxy.cfg", '/tmp/haproxy.cfg')
        else
          ssh.scp.upload!("output/#{name}/config.yaml", '/tmp/config.yaml')
        end

        # 上传安装脚本
        ssh.scp.upload!("output/#{name}/install.sh", '/tmp/install.sh')

        log("⚙️  在 #{name} 上执行安装...")
        output = ssh.exec!('sudo bash /tmp/install.sh 2>&1')
        log("📋 #{name} 安装输出:")
        log(output)

        log("✅ #{name} 部署完成")
      end
    rescue StandardError => e
      log("❌ #{name} 部署失败: #{e.message}")
      @logger.error("#{name} deployment failed: #{e.message}")
      @logger.error(e.backtrace.join("\n"))
    end
  end

  # 配置现有服务器节点的 kubectl
  def configure_kubectl_on_servers
    log('🔧 配置所有服务器节点的 kubectl...')

    @server_nodes.each do |node|
      configure_kubectl_on_node(node)
    end
  end

  # 为所有服务器节点安装 k9s 和 helm
  def install_k9s_helm_on_servers
    log('📦 为所有服务器节点安装 k9s 和 helm...')

    @server_nodes.each do |node|
      install_k9s_helm_on_node(node)
    end
  end

  # 为单个节点安装 k9s 和 helm
  def install_k9s_helm_on_node(node)
    return unless node['role'] == 'server'

    log("📦 为 #{node['name']} 安装 k9s 和 helm...")

    begin
      Net::SSH.start(node['ip'], node['ssh_user'], timeout: 30) do |ssh|
        k9s_helm_script = <<~SH
                    #!/bin/bash
                    set -e
                    echo "📦 安装 k9s 和 helm 到 #{node['name']}..."

                    # 安装 k9s
                    echo "📦 安装 k9s..."
                    K9S_VERSION=$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\\1/')
                    echo "  下载 k9s $K9S_VERSION..."

                    # 检测系统架构
                    ARCH=$(uname -m)
                    case $ARCH in
                      x86_64) K9S_ARCH="amd64" ;;
                      aarch64) K9S_ARCH="arm64" ;;
                      *) K9S_ARCH="amd64" ;;
                    esac

                    curl -sL "https://github.com/derailed/k9s/releases/download/$K9S_VERSION/k9s_Linux_$K9S_ARCH.tar.gz" -o /tmp/k9s.tar.gz
                    tar -xzf /tmp/k9s.tar.gz -C /tmp
                    mv /tmp/k9s /usr/local/bin/k9s
                    chmod +x /usr/local/bin/k9s
                    rm -f /tmp/k9s.tar.gz /tmp/LICENSE /tmp/README.md

                    # 验证 k9s 安装
                    if k9s version >/dev/null 2>&1; then
                      echo "  ✅ k9s 安装成功: $(k9s version --short)"
                    else
                      echo "  ⚠️  k9s 安装可能有问题"
                    fi

                    # 安装 helm
                    echo "📦 安装 helm..."
                    curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
                    chmod 700 /tmp/get_helm.sh
                    HELM_INSTALL_DIR="/usr/local/bin" /tmp/get_helm.sh --no-sudo >/dev/null 2>&1
                    rm -f /tmp/get_helm.sh

                    # 验证 helm 安装
                    if helm version >/dev/null 2>&1; then
                      echo "  ✅ helm 安装成功: $(helm version --short)"
                    else
                      echo "  ⚠️  helm 安装可能有问题"
                    fi

                    # 初始化 helm
                    echo "🔧 初始化 helm..."
                    export KUBECONFIG=/root/.kube/config
                    helm repo add stable https://charts.helm.sh/stable >/dev/null 2>&1 || true
                    helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || true
                    helm repo update >/dev/null 2>&1 || true
                    echo "  ✅ helm 仓库初始化完成"

                    # 创建 k9s 配置目录
                    echo "🔧 配置 k9s..."
                    mkdir -p /root/.config/k9s

                    # 创建 k9s 基础配置
                    cat > /root/.config/k9s/config.yml << 'EOF'
          k9s:
            liveViewAutoRefresh: true
            refreshRate: 2
            maxConnRetry: 5
            readOnly: false
            noExitOnCtrlC: false
            ui:
              enableMouse: true
              headless: false
              logoless: false
              crumbsless: false
              reactive: false
              noIcons: false
            skipLatestRevCheck: false
            disablePodCounting: false
            shellPod:
              image: busybox:1.35.0
              namespace: default
              limits:
                cpu: 100m
                memory: 100Mi
            imageScanner:
              enable: false
            logger:
              tail: 100
              buffer: 5000
              sinceSeconds: -1
              textWrap: false
              showTime: false
          EOF

                    echo ""
                    echo "🎉 k9s 和 helm 安装完成！"
                    echo ""
                    echo "💡 可用工具："
                    echo "   kubectl get nodes          # Kubernetes 命令行工具"
                    echo "   k get pods --all-namespaces # kubectl 别名"
                    echo "   k9s                        # 终端 UI 集群管理工具"
                    echo "   helm list                  # Kubernetes 包管理器"
                    echo ""
                    echo "🚀 k9s 使用提示："
                    echo "   - 按 ':' 进入命令模式"
                    echo "   - 输入资源名称快速跳转 (pods, svc, deploy 等)"
                    echo "   - 按 '?' 查看帮助"
                    echo "   - 按 'Ctrl+C' 退出"
                    echo ""
        SH

        # 上传并执行安装脚本
        ssh.scp.upload!(StringIO.new(k9s_helm_script), '/tmp/install_k9s_helm.sh')
        ssh.exec!('chmod +x /tmp/install_k9s_helm.sh')

        log("⚙️  在 #{node['name']} 上安装 k9s 和 helm...")
        output = ssh.exec!('sudo bash /tmp/install_k9s_helm.sh 2>&1')
        log("📋 #{node['name']} k9s 和 helm 安装输出:")
        log(output)

        # 清理临时文件
        ssh.exec!('rm -f /tmp/install_k9s_helm.sh')

        log("✅ #{node['name']} k9s 和 helm 安装完成")
      end
    rescue StandardError => e
      log("❌ #{node['name']} k9s 和 helm 安装失败: #{e.message}")
      @logger.error("#{node['name']} k9s and helm installation failed: #{e.message}")
    end
  end

  # 为单个节点配置 kubectl
  def configure_kubectl_on_node(node)
    return unless node['role'] == 'server'

    log("🔧 配置 #{node['name']} 的 kubectl...")

    begin
      Net::SSH.start(node['ip'], node['ssh_user'], timeout: 30) do |ssh|
        kubectl_config_script = <<~SH
                    #!/bin/bash
                    set -e
                    echo "🔧 配置 kubectl for root 用户..."

                    # 检查 kubeconfig 文件是否存在
                    if [ ! -f /etc/rancher/rke2/rke2.yaml ]; then
                      echo "❌ RKE2 kubeconfig 文件不存在，请确保 RKE2 已正确安装"
                      exit 1
                    fi

                    # 创建 kubectl 软链接到系统 PATH
                    echo "🔗 创建 kubectl 软链接..."
                    ln -sf /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
                    chmod +x /usr/local/bin/kubectl

                    # 为 root 用户设置 kubeconfig
                    echo "📝 为 root 用户配置 kubeconfig..."
                    mkdir -p /root/.kube
                    cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
                    chmod 600 /root/.kube/config
                    chown root:root /root/.kube/config

                    # 设置环境变量到 root 的 bashrc
                    echo "🔧 配置环境变量..."
                    if ! grep -q "KUBECONFIG" /root/.bashrc; then
                      echo "# RKE2 kubectl configuration" >> /root/.bashrc
                      echo "export KUBECONFIG=/root/.kube/config" >> /root/.bashrc
                      echo "export PATH=/var/lib/rancher/rke2/bin:\\$PATH" >> /root/.bashrc
                      echo "alias k=kubectl" >> /root/.bashrc
                    fi

                    # 设置环境变量到 root 的 profile
                    if ! grep -q "KUBECONFIG" /root/.profile; then
                      echo "# RKE2 kubectl configuration" >> /root/.profile
                      echo "export KUBECONFIG=/root/.kube/config" >> /root/.profile
                      echo "export PATH=/var/lib/rancher/rke2/bin:\\$PATH" >> /root/.profile
                    fi

                    # 测试 kubectl 配置
                    echo "🧪 测试 kubectl 配置..."
                    export KUBECONFIG=/root/.kube/config
                    export PATH=/var/lib/rancher/rke2/bin:\\$PATH

                    # 验证 kubectl 功能
                    echo "🔍 验证 kubectl 功能..."
                    if kubectl get nodes >/dev/null 2>&1; then
                      echo "✅ kubectl 配置成功！"
                      echo "📊 当前集群节点:"
                      kubectl get nodes
                    else
                      echo "⚠️  kubectl 可能需要 API 服务器完全就绪后才能正常工作"
                    fi

                    echo ""
                    echo "🎉 kubectl 配置完成！"
                    echo "💡 提示: 重新登录 root 用户后，可以直接使用以下命令:"
                    echo "   kubectl get nodes"
                    echo "   k get pods --all-namespaces"
                    echo ""

                    # 安装 k9s
                    echo "📦 安装 k9s..."
                    K9S_VERSION=$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\\1/')
                    echo "  下载 k9s $K9S_VERSION..."

                    # 检测系统架构
                    ARCH=$(uname -m)
                    case $ARCH in
                      x86_64) K9S_ARCH="amd64" ;;
                      aarch64) K9S_ARCH="arm64" ;;
                      *) K9S_ARCH="amd64" ;;
                    esac

                    curl -sL "https://github.com/derailed/k9s/releases/download/$K9S_VERSION/k9s_Linux_$K9S_ARCH.tar.gz" -o /tmp/k9s.tar.gz
                    tar -xzf /tmp/k9s.tar.gz -C /tmp
                    mv /tmp/k9s /usr/local/bin/k9s
                    chmod +x /usr/local/bin/k9s
                    rm -f /tmp/k9s.tar.gz /tmp/LICENSE /tmp/README.md

                    # 验证 k9s 安装
                    if k9s version >/dev/null 2>&1; then
                      echo "  ✅ k9s 安装成功: $(k9s version --short)"
                    else
                      echo "  ⚠️  k9s 安装可能有问题"
                    fi

                    # 安装 helm
                    echo "📦 安装 helm..."
                    curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
                    chmod 700 /tmp/get_helm.sh
                    HELM_INSTALL_DIR="/usr/local/bin" /tmp/get_helm.sh --no-sudo >/dev/null 2>&1
                    rm -f /tmp/get_helm.sh

                    # 验证 helm 安装
                    if helm version >/dev/null 2>&1; then
                      echo "  ✅ helm 安装成功: $(helm version --short)"
                    else
                      echo "  ⚠️  helm 安装可能有问题"
                    fi

                    # 初始化 helm
                    echo "🔧 初始化 helm..."
                    export KUBECONFIG=/root/.kube/config
                    helm repo add stable https://charts.helm.sh/stable >/dev/null 2>&1 || true
                    helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || true
                    helm repo update >/dev/null 2>&1 || true
                    echo "  ✅ helm 仓库初始化完成"

                    # 创建 k9s 配置目录
                    echo "🔧 配置 k9s..."
                    mkdir -p /root/.config/k9s

                    # 创建 k9s 基础配置
                    cat > /root/.config/k9s/config.yml << 'EOF'
          k9s:
            liveViewAutoRefresh: true
            refreshRate: 2
            maxConnRetry: 5
            readOnly: false
            noExitOnCtrlC: false
            ui:
              enableMouse: true
              headless: false
              logoless: false
              crumbsless: false
              reactive: false
              noIcons: false
            skipLatestRevCheck: false
            disablePodCounting: false
            shellPod:
              image: busybox:1.35.0
              namespace: default
              limits:
                cpu: 100m
                memory: 100Mi
            imageScanner:
              enable: false
            logger:
              tail: 100
              buffer: 5000
              sinceSeconds: -1
              textWrap: false
              showTime: false
          EOF

                    echo ""
                    echo "🎉 k9s 和 helm 安装完成！"
                    echo ""
                    echo "💡 可用工具："
                    echo "   kubectl get nodes          # Kubernetes 命令行工具"
                    echo "   k get pods --all-namespaces # kubectl 别名"
                    echo "   k9s                        # 终端 UI 集群管理工具"
                    echo "   helm list                  # Kubernetes 包管理器"
                    echo ""
                    echo "🚀 k9s 使用提示："
                    echo "   - 按 ':' 进入命令模式"
                    echo "   - 输入资源名称快速跳转 (pods, svc, deploy 等)"
                    echo "   - 按 '?' 查看帮助"
                    echo "   - 按 'Ctrl+C' 退出"
                    echo ""
        SH

        # 上传并执行配置脚本
        ssh.scp.upload!(StringIO.new(kubectl_config_script), '/tmp/configure_kubectl.sh')
        ssh.exec!('chmod +x /tmp/configure_kubectl.sh')

        log("⚙️  在 #{node['name']} 上配置 kubectl...")
        output = ssh.exec!('sudo bash /tmp/configure_kubectl.sh 2>&1')
        log("📋 #{node['name']} kubectl 配置输出:")
        log(output)

        # 清理临时文件
        ssh.exec!('rm -f /tmp/configure_kubectl.sh')

        log("✅ #{node['name']} kubectl 配置完成")
      end
    rescue StandardError => e
      log("❌ #{node['name']} kubectl 配置失败: #{e.message}")
      @logger.error("#{node['name']} kubectl configuration failed: #{e.message}")
    end
  end

  def fix_ingress_rbac
    log('🔧 修复 Ingress Controller RBAC 权限...')

    return if @server_nodes.empty?

    first_server = @server_nodes.first
    log("📝 在 #{first_server['name']} 上修复 Ingress RBAC 权限...")

    begin
      Net::SSH.start(first_server['ip'], first_server['ssh_user'], timeout: 30) do |ssh|
        # 等待集群就绪
        log('⏳ 等待集群 API 完全就绪...')
        wait_for_api_ready(ssh)

        # 生成修复的 RBAC 配置
        rbac_fix_config = generate_rbac_fix_manifest
        ssh.scp.upload!(StringIO.new(rbac_fix_config), '/tmp/nginx-ingress-rbac-fix.yaml')

        log('🚀 应用修复的 RBAC 权限...')

        # 应用配置
        output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl apply -f /tmp/nginx-ingress-rbac-fix.yaml 2>&1')
        log('📋 RBAC 修复输出:')
        log(output)

        # 重启 Ingress Pod 以应用新权限
        log('🔄 重启 Ingress Controller Pods...')
        restart_output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx rollout restart daemonset/nginx-ingress-controller 2>&1')
        log(restart_output)

        # 等待重启完成
        log('⏳ 等待 Ingress Pods 重启完成...')
        ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx rollout status daemonset/nginx-ingress-controller --timeout=300s')

        # 验证修复状态
        log('🔍 验证 Ingress Controller 状态...')
        status_output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx get pods')
        log('📊 Ingress Controller 状态:')
        log(status_output)

        # 检查权限是否修复
        log('🧪 测试权限修复...')
        test_output = ssh.exec!('export KUBECONFIG=/etc/rancher/rke2/rke2.yaml && /var/lib/rancher/rke2/bin/kubectl -n ingress-nginx logs daemonset/nginx-ingress-controller --tail=10 2>&1 | grep -E "(error|Error|forbidden|Forbidden)" || echo "No permission errors found"')
        log("权限测试结果: #{test_output}")

        # 清理临时文件
        ssh.exec!('rm -f /tmp/nginx-ingress-rbac-fix.yaml')

        log('✅ Ingress Controller RBAC 权限修复完成!')
      end
    rescue StandardError => e
      log("❌ Ingress RBAC 权限修复失败: #{e.message}")
      @logger.error("Ingress RBAC fix failed: #{e.message}")
    end
  end

  def generate_rbac_fix_manifest
    <<~YAML
      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRole
      metadata:
        name: nginx-ingress-clusterrole
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      rules:
        - apiGroups: [""]
          resources: ["configmaps", "endpoints", "nodes", "pods", "secrets", "namespaces"]
          verbs: ["list", "watch", "get"]
        - apiGroups: [""]
          resources: ["services"]
          verbs: ["get", "list", "watch"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingresses"]
          verbs: ["get", "list", "watch"]
        - apiGroups: [""]
          resources: ["events"]
          verbs: ["create", "patch"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingresses/status"]
          verbs: ["update"]
        - apiGroups: ["networking.k8s.io"]
          resources: ["ingressclasses"]
          verbs: ["get", "list", "watch"]
        - apiGroups: ["coordination.k8s.io"]
          resources: ["leases"]
          verbs: ["list", "watch", "get", "update", "create"]
        - apiGroups: ["discovery.k8s.io"]
          resources: ["endpointslices"]
          verbs: ["list", "watch", "get"]
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: Role
      metadata:
        name: nginx-ingress-role
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      rules:
        - apiGroups: [""]
          resources: ["configmaps", "pods", "secrets", "namespaces"]
          verbs: ["get"]
        - apiGroups: [""]
          resources: ["configmaps"]
          resourceNames: ["ingress-controller-leader"]
          verbs: ["get", "update"]
        - apiGroups: [""]
          resources: ["configmaps"]
          verbs: ["create"]
        - apiGroups: ["coordination.k8s.io"]
          resources: ["leases"]
          verbs: ["get", "create", "update"]
        - apiGroups: [""]
          resources: ["endpoints"]
          verbs: ["get"]
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: RoleBinding
      metadata:
        name: nginx-ingress-role-nisa-binding
        namespace: ingress-nginx
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      roleRef:
        apiGroup: rbac.authorization.k8s.io
        kind: Role
        name: nginx-ingress-role
      subjects:
        - kind: ServiceAccount
          name: nginx-ingress-serviceaccount
          namespace: ingress-nginx
      ---
      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRoleBinding
      metadata:
        name: nginx-ingress-clusterrole-nisa-binding
        labels:
          app.kubernetes.io/name: ingress-nginx
          app.kubernetes.io/part-of: ingress-nginx
      roleRef:
        apiGroup: rbac.authorization.k8s.io
        kind: ClusterRole
        name: nginx-ingress-clusterrole
      subjects:
        - kind: ServiceAccount
          name: nginx-ingress-serviceaccount
          namespace: ingress-nginx
    YAML
  end
end

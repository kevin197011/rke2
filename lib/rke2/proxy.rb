# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require_relative 'config'
require_relative 'helper'
require_relative 'logger'

module RKE2
  # HAProxy configuration class for RKE2 load balancer nodes
  class Proxy
    include RKE2::Config

    attr_reader :logger, :helper, :config

    # Initialize proxy with configuration
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @helper = RKE2::Helper.new(logger: @logger)
      @config_file = config_file
      @config = nil
    end

    # Configure HAProxy on all load balancer nodes
    #
    # @return [Boolean] True if all LB nodes configured successfully
    def configure_all_lb_nodes
      @logger.deploy('🔗 开始配置 HAProxy 负载均衡')

      load_configuration
      validate_configuration

      lb_nodes = extract_lb_nodes
      server_nodes = extract_server_nodes

      if lb_nodes.empty?
        @logger.error('配置文件中未找到负载均衡节点 (role: lb)')
        return false
      end

      if server_nodes.empty?
        @logger.error('配置文件中未找到服务器节点 (role: server)')
        return false
      end

      @logger.info("发现 #{lb_nodes.length} 个负载均衡节点，#{server_nodes.length} 个服务器节点")

      success_count = 0
      failed_nodes = []

      lb_nodes.each_with_index do |node, index|
        @logger.step(index + 1, lb_nodes.length, "配置负载均衡节点 #{node[:name]} HAProxy")

        if configure_lb_node(node, server_nodes)
          success_count += 1
          @logger.success("节点 #{node[:name]} HAProxy 配置完成")
        else
          failed_nodes << node[:name]
          @logger.error("节点 #{node[:name]} HAProxy 配置失败")
        end
      end

      # Summary
      if failed_nodes.empty?
        @logger.success("🎉 所有 #{lb_nodes.length} 个负载均衡节点 HAProxy 配置完成！")
        true
      else
        @logger.error("❌ #{failed_nodes.length} 个负载均衡节点 HAProxy 配置失败: #{failed_nodes.join(', ')}")
        @logger.info("✅ #{success_count} 个负载均衡节点 HAProxy 配置成功")
        false
      end
    end

    # Configure HAProxy on a single load balancer node
    #
    # @param lb_node [Hash] Load balancer node configuration
    # @param server_nodes [Array<Hash>] Array of server node configurations
    # @return [Boolean] True if configuration successful
    def configure_lb_node(lb_node, server_nodes)
      @logger.time("节点 #{lb_node[:name]} HAProxy 配置") do
        # Test connectivity first
        unless test_node_connectivity(lb_node)
          @logger.error("负载均衡节点 #{lb_node[:name]} 连接测试失败")
          return false
        end

        # Generate and upload HAProxy configuration script
        script_content = generate_haproxy_script(lb_node, server_nodes)
        script_path = "/tmp/rke2_haproxy_#{lb_node[:name]}_#{Time.now.to_i}.sh"

        # Upload script
        @logger.loading("上传 HAProxy 配置脚本到 #{lb_node[:name]}")
        upload_result = @helper.ssh_upload_content(
          lb_node[:ip],
          lb_node[:username],
          script_content,
          script_path,
          lb_node[:ssh_key]
        )

        unless upload_result[:success]
          @logger.error("脚本上传失败: #{upload_result[:error]}")
          return false
        end

        # Execute HAProxy configuration script
        @logger.loading('执行 HAProxy 配置脚本')
        exec_result = @helper.ssh_exec(
          lb_node[:ip],
          lb_node[:username],
          "chmod +x #{script_path} && #{script_path}",
          lb_node[:ssh_key]
        )

        # Cleanup script
        @helper.ssh_exec(lb_node[:ip], lb_node[:username], "rm -f #{script_path}", lb_node[:ssh_key], skip_sudo: false)

        if exec_result[:success]
          @logger.info('HAProxy 配置脚本执行完成', {
                         node: lb_node[:name],
                         output_length: exec_result[:output].length
                       })

          # Log script output if in debug mode
          @logger.debug("HAProxy 配置脚本输出:\n#{exec_result[:output]}") if @logger.logger.level <= ::Logger::DEBUG

          # Verify HAProxy configuration
          verify_haproxy_config(lb_node)
        else
          @logger.error('HAProxy 配置脚本执行失败', {
                          node: lb_node[:name],
                          error: exec_result[:error],
                          exit_code: exec_result[:exit_code]
                        })
          false
        end
      end
    rescue StandardError => e
      @logger.error("负载均衡节点 #{lb_node[:name]} HAProxy 配置异常: #{e.message}")
      false
    end

    private

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

      # Validate token
      @logger.warn('配置文件中未设置 token，HAProxy 配置可能不完整') if @config['token'].nil? || @config['token'].to_s.strip.empty?

      @logger.info('配置文件验证通过')
    end

    # Extract load balancer nodes from configuration
    #
    # @return [Array<Hash>] Array of load balancer node configurations
    def extract_lb_nodes
      @config['nodes'].select { |node| node['role'] == 'lb' }.map do |node|
        {
          name: node['name'],
          ip: node['ip'],
          role: node['role'],
          username: node['username'] || @config['username'] || 'root',
          ssh_key: node['ssh_key'] || @config['ssh_key'] || '~/.ssh/id_rsa'
        }
      end
    end

    # Extract server nodes from configuration
    #
    # @return [Array<Hash>] Array of server node configurations
    def extract_server_nodes
      @config['nodes'].select { |node| node['role'] == 'server' }.map do |node|
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

      @logger.success("节点 #{node[:name]} 连接测试通过")
      true
    end

    # Generate HAProxy configuration script for a load balancer node
    #
    # @param lb_node [Hash] Load balancer node configuration
    # @param server_nodes [Array<Hash>] Array of server node configurations
    # @return [String] HAProxy configuration script content
    def generate_haproxy_script(lb_node, server_nodes)
      token = @config['token'] || 'rke2Secret123456'
      loadbalancer_ip = @config['loadbalancer_ip'] || lb_node[:ip]

      # Generate server list for HAProxy
      server_list = server_nodes.map.with_index do |server, _index|
        "    server #{server[:name]} #{server[:ip]}:6443 check"
      end.join("\n")

      server_list_9345 = server_nodes.map.with_index do |server, _index|
        "    server #{server[:name]} #{server[:ip]}:9345 check"
      end.join("\n")

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

        log_info "🔗 开始配置负载均衡节点 #{lb_node[:name]} 的 HAProxy..."

        # Get system information
        log_info "📊 系统信息:"
        echo "  主机名: $(hostname)"
        echo "  系统版本: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
        echo "  内核版本: $(uname -r)"
        echo "  负载均衡器IP: #{loadbalancer_ip}"

        # Install HAProxy
        log_info "📦 安装 HAProxy..."
        install_haproxy() {
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y haproxy
            elif command -v yum >/dev/null 2>&1; then
                yum install -y haproxy
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y haproxy
            elif command -v zypper >/dev/null 2>&1; then
                zypper install -y haproxy
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm haproxy
            else
                log_error "无法识别的包管理器，请手动安装 HAProxy"
                exit 1
            fi
        }
        install_haproxy
        log_success "HAProxy 安装完成"

        # Backup original configuration
        log_info "💾 备份原始配置..."
        if [ -f /etc/haproxy/haproxy.cfg ]; then
            cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup.$(date +%Y%m%d_%H%M%S)
            log_success "原始配置已备份"
        fi

        # Generate HAProxy configuration
        log_info "🔧 生成 HAProxy 配置..."
        cat > /etc/haproxy/haproxy.cfg << 'EOF'
        #---------------------------------------------------------------------
        # RKE2 HAProxy Configuration
        # Generated by RKE2 Deployment Tool
        #---------------------------------------------------------------------

        #---------------------------------------------------------------------
        # Global settings
        #---------------------------------------------------------------------
        global
            log         127.0.0.1:514 local0
            chroot      /var/lib/haproxy
            stats       socket /run/haproxy/admin.sock mode 660 level admin
            stats       timeout 30s
            user        haproxy
            group       haproxy
            daemon

            # Default SSL material locations
            ca-base     /etc/ssl/certs
            crt-base    /etc/ssl/private

            # Tune SSL defaults
            ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
            ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

        #---------------------------------------------------------------------
        # Common defaults that all the 'listen' and 'backend' sections will
        # use if not designated in their block
        #---------------------------------------------------------------------
        defaults
            mode                    http
            log                     global
            option                  httplog
            option                  dontlognull
            option                  http-server-close
            option                  forwardfor       except 127.0.0.0/8
            option                  redispatch
            retries                 3
            timeout http-request    10s
            timeout queue           1m
            timeout connect         10s
            timeout client          1m
            timeout server          1m
            timeout http-keep-alive 10s
            timeout check           10s
            maxconn                 3000

        #---------------------------------------------------------------------
        # HAProxy Statistics
        #---------------------------------------------------------------------
        listen stats
            bind *:8404
            stats enable
            stats uri /stats
            stats refresh 30s
            stats admin if TRUE
            stats realm HAProxy\\ Statistics
            stats auth admin:rke2admin

        #---------------------------------------------------------------------
        # RKE2 Kubernetes API Server (6443)
        #---------------------------------------------------------------------
        frontend rke2-api-frontend
            bind *:6443
            mode tcp
            option tcplog
            default_backend rke2-api-backend

        backend rke2-api-backend
            mode tcp
            option tcp-check
            balance roundrobin
        #{server_list}

        #---------------------------------------------------------------------
        # RKE2 Registration Server (9345)
        #---------------------------------------------------------------------
        frontend rke2-registration-frontend
            bind *:9345
            mode tcp
            option tcplog
            default_backend rke2-registration-backend

        backend rke2-registration-backend
            mode tcp
            option tcp-check
            balance roundrobin
        #{server_list_9345}

        #---------------------------------------------------------------------
        # RKE2 Supervisor API (9001) - Optional
        #---------------------------------------------------------------------
        frontend rke2-supervisor-frontend
            bind *:9001
            mode tcp
            option tcplog
            default_backend rke2-supervisor-backend

        backend rke2-supervisor-backend
            mode tcp
            option tcp-check
            balance roundrobin
        #{server_nodes.map { |server| "    server #{server[:name]} #{server[:ip]}:9001 check" }.join("\n")}

        #---------------------------------------------------------------------
        # Health Check Endpoint
        #---------------------------------------------------------------------
        frontend health-check
            bind *:8080
            mode http
            monitor-uri /health
            monitor fail if FALSE

        EOF

        log_success "HAProxy 配置文件已生成"

        # Configure rsyslog for HAProxy logging
        log_info "📝 配置日志..."
        configure_logging() {
            # Enable UDP syslog reception
            if [ -f /etc/rsyslog.conf ]; then
                if ! grep -q "^\\$ModLoad imudp" /etc/rsyslog.conf; then
                    echo '\\$ModLoad imudp' >> /etc/rsyslog.conf
                    echo '\\$UDPServerRun 514' >> /etc/rsyslog.conf
                    echo '\\$UDPServerAddress 127.0.0.1' >> /etc/rsyslog.conf
                fi

                # Create HAProxy log configuration
                cat > /etc/rsyslog.d/49-haproxy.conf << 'EOF_LOG'
        \\$ModLoad imudp
        \\$UDPServerRun 514
        \\$UDPServerAddress 127.0.0.1

        # HAProxy log files
        local0.*    /var/log/haproxy.log
        & stop
        EOF_LOG

                # Restart rsyslog
                systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || true
                log_success "日志配置完成"
            fi
        }
        configure_logging

        # Test HAProxy configuration
        log_info "🔍 测试 HAProxy 配置..."
        if haproxy -f /etc/haproxy/haproxy.cfg -c; then
            log_success "HAProxy 配置文件语法检查通过"
        else
            log_error "HAProxy 配置文件语法检查失败"
            exit 1
        fi

        # Enable and start HAProxy service
        log_info "🚀 启动 HAProxy 服务..."
        systemctl enable haproxy
        systemctl restart haproxy

        # Wait for service to start
        sleep 3

        # Check service status
        if systemctl is-active --quiet haproxy; then
            log_success "HAProxy 服务已成功启动"
        else
            log_error "HAProxy 服务启动失败"
            systemctl status haproxy
            exit 1
        fi

        # Configure firewall
        log_info "🔥 配置防火墙..."
        configure_firewall() {
            # Open required ports: 6443 (K8s API), 9345 (RKE2 registration), 9001 (supervisor), 8404 (stats), 8080 (health)
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 6443/tcp
                ufw allow 9345/tcp
                ufw allow 9001/tcp
                ufw allow 8404/tcp
                ufw allow 8080/tcp
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=6443/tcp
                firewall-cmd --permanent --add-port=9345/tcp
                firewall-cmd --permanent --add-port=9001/tcp
                firewall-cmd --permanent --add-port=8404/tcp
                firewall-cmd --permanent --add-port=8080/tcp
                firewall-cmd --reload
            elif command -v iptables >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
                iptables -A INPUT -p tcp --dport 9345 -j ACCEPT
                iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
                iptables -A INPUT -p tcp --dport 8404 -j ACCEPT
                iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
            fi
        }
        configure_firewall
        log_success "防火墙规则已配置"

        # Display service information
        log_info "📊 服务状态信息:"
        echo "  HAProxy 状态: $(systemctl is-active haproxy)"
        echo "  HAProxy 进程: $(ps aux | grep -c '[h]aproxy')"
        echo "  监听端口检查:"
        netstat -tlnp 2>/dev/null | grep -E ':(6443|9345|9001|8404|8080)' | while read line; do
            echo "    $line"
        done || true

        # Test endpoints
        log_info "🔍 测试服务端点..."
        test_endpoints() {
            # Test health check endpoint
            if curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
                log_success "健康检查端点 (8080) 正常"
            else
                log_warning "健康检查端点 (8080) 测试失败"
            fi

            # Test stats endpoint (without auth check)
            if curl -s -f http://localhost:8404/stats >/dev/null 2>&1; then
                log_success "统计信息端点 (8404) 正常"
            else
                log_warning "统计信息端点 (8404) 需要认证"
            fi
        }
        test_endpoints

        log_success "🎉 负载均衡节点 #{lb_node[:name]} HAProxy 配置完成！"

        log_info "📈 HAProxy 配置摘要:"
        echo "  - ✅ HAProxy 已安装并启动"
        echo "  - ✅ RKE2 API Server 负载均衡 (端口 6443)"
        echo "  - ✅ RKE2 注册服务负载均衡 (端口 9345)"
        echo "  - ✅ RKE2 Supervisor 负载均衡 (端口 9001)"
        echo "  - ✅ HAProxy 统计信息 (端口 8404)"
        echo "  - ✅ 健康检查端点 (端口 8080)"
        echo "  - ✅ 防火墙规则已配置"
        echo "  - ✅ 日志配置已启用"

        log_info "🌐 访问信息:"
        echo "  负载均衡器地址: #{loadbalancer_ip}"
        echo "  Kubernetes API: https://#{loadbalancer_ip}:6443"
        echo "  RKE2 注册服务: https://#{loadbalancer_ip}:9345"
        echo "  HAProxy 统计页面: http://#{loadbalancer_ip}:8404/stats"
        echo "    用户名: admin"
        echo "    密码: rke2admin"
        echo "  健康检查: http://#{loadbalancer_ip}:8080/health"

        log_info "💡 使用说明:"
        echo "  - Agent 节点应连接到: https://#{loadbalancer_ip}:9345"
        echo "  - Kubectl 应配置为: https://#{loadbalancer_ip}:6443"
        echo "  - 使用 token: #{token}"
        echo "  - 查看 HAProxy 日志: tail -f /var/log/haproxy.log"
        echo "  - 重启 HAProxy: systemctl restart haproxy"

        exit 0
      SCRIPT
    end

    # Verify HAProxy configuration
    #
    # @param lb_node [Hash] Load balancer node configuration
    # @return [Boolean] True if verification passes
    def verify_haproxy_config(lb_node)
      @logger.debug('验证 HAProxy 配置', { node: lb_node[:name] })

      verification_commands = {
        haproxy_installed: 'command -v haproxy && echo "installed" || echo "missing"',
        haproxy_running: 'systemctl is-active haproxy 2>/dev/null || echo "inactive"',
        config_exists: 'test -f /etc/haproxy/haproxy.cfg && echo "exists" || echo "missing"',
        port_6443: 'netstat -tlnp 2>/dev/null | grep ":6443" | wc -l',
        port_9345: 'netstat -tlnp 2>/dev/null | grep ":9345" | wc -l',
        health_check: 'curl -s -f http://localhost:8080/health >/dev/null 2>&1 && echo "ok" || echo "fail"'
      }

      verification_results = {}

      verification_commands.each do |check, command|
        result = @helper.ssh_exec(lb_node[:ip], lb_node[:username], command, lb_node[:ssh_key])
        verification_results[check] = {
          success: result[:success],
          output: result[:output]&.strip
        }
      end

      # Check results
      checks_passed = 0
      total_checks = verification_commands.length

      # HAProxy should be installed
      if verification_results[:haproxy_installed][:success] &&
         verification_results[:haproxy_installed][:output] == 'installed'
        checks_passed += 1
        @logger.debug('✅ HAProxy 安装检查通过')
      else
        @logger.debug('❌ HAProxy 安装检查失败')
      end

      # HAProxy should be running
      if verification_results[:haproxy_running][:success] &&
         verification_results[:haproxy_running][:output] == 'active'
        checks_passed += 1
        @logger.debug('✅ HAProxy 服务状态检查通过')
      else
        @logger.debug('❌ HAProxy 服务状态检查失败')
      end

      # Configuration file should exist
      if verification_results[:config_exists][:success] &&
         verification_results[:config_exists][:output] == 'exists'
        checks_passed += 1
        @logger.debug('✅ HAProxy 配置文件检查通过')
      else
        @logger.debug('❌ HAProxy 配置文件检查失败')
      end

      # Port 6443 should be listening
      if verification_results[:port_6443][:success] &&
         verification_results[:port_6443][:output].to_i > 0
        checks_passed += 1
        @logger.debug('✅ 端口 6443 监听检查通过')
      else
        @logger.debug('❌ 端口 6443 监听检查失败')
      end

      # Port 9345 should be listening
      if verification_results[:port_9345][:success] &&
         verification_results[:port_9345][:output].to_i > 0
        checks_passed += 1
        @logger.debug('✅ 端口 9345 监听检查通过')
      else
        @logger.debug('❌ 端口 9345 监听检查失败')
      end

      # Health check should work
      if verification_results[:health_check][:success] &&
         verification_results[:health_check][:output] == 'ok'
        checks_passed += 1
        @logger.debug('✅ 健康检查端点检查通过')
      else
        @logger.debug('❌ 健康检查端点检查失败')
      end

      success_rate = (checks_passed.to_f / total_checks * 100).round(1)
      @logger.info("HAProxy 验证完成: #{checks_passed}/#{total_checks} 项检查通过 (#{success_rate}%)", {
                     node: lb_node[:name],
                     checks_passed: checks_passed,
                     total_checks: total_checks,
                     success_rate: success_rate
                   })

      checks_passed >= (total_checks * 0.75).ceil # At least 75% checks should pass
    end

    # Class methods for easy access
    class << self
      # Configure HAProxy on all load balancer nodes
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if all LB nodes configured successfully
      def configure_haproxy(config_file = 'config.yml', logger: nil)
        proxy = new(config_file, logger: logger)
        proxy.configure_all_lb_nodes
      end

      # Configure HAProxy on a specific load balancer node
      #
      # @param lb_node_name [String] Name of the load balancer node to configure
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if LB node configured successfully
      def configure_haproxy_node(lb_node_name, config_file = 'config.yml', logger: nil)
        proxy = new(config_file, logger: logger)
        proxy.load_configuration

        lb_nodes = proxy.extract_lb_nodes
        server_nodes = proxy.extract_server_nodes
        target_node = lb_nodes.find { |node| node[:name] == lb_node_name }

        unless target_node
          proxy.logger.error("负载均衡节点 '#{lb_node_name}' 在配置文件中未找到")
          return false
        end

        if server_nodes.empty?
          proxy.logger.error('配置文件中未找到服务器节点 (role: server)')
          return false
        end

        proxy.logger.deploy("🔗 开始配置负载均衡节点 #{lb_node_name} HAProxy")
        result = proxy.configure_lb_node(target_node, server_nodes)

        if result
          proxy.logger.success("🎉 负载均衡节点 #{lb_node_name} HAProxy 配置完成！")
        else
          proxy.logger.error("❌ 负载均衡节点 #{lb_node_name} HAProxy 配置失败")
        end

        result
      end
    end
  end
end

# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require_relative 'config'
require_relative 'helper'
require_relative 'logger'

module RKE2
  # RKE2 Server deployment class for master nodes
  class Server
    include RKE2::Config

    attr_reader :logger, :helper, :config

    # Initialize server with configuration
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @helper = RKE2::Helper.new(logger: @logger)
      @config_file = config_file
      @config = nil
    end

    # Deploy RKE2 server on all server nodes
    #
    # @return [Boolean] True if all server nodes deployed successfully
    def deploy_all_servers
      @logger.deploy('🚀 开始部署 RKE2 Server 节点')

      load_configuration
      validate_configuration

      server_nodes = extract_server_nodes

      if server_nodes.empty?
        @logger.error('配置文件中未找到服务器节点 (role: server)')
        return false
      end

      @logger.info("发现 #{server_nodes.length} 个服务器节点需要部署")

      success_count = 0
      failed_nodes = []

      # Deploy first server node (initial server)
      first_server = server_nodes.first
      @logger.step(1, server_nodes.length, "部署第一个服务器节点 #{first_server[:name]} (初始化集群)")

      if deploy_first_server(first_server)
        success_count += 1
        @logger.success("第一个服务器节点 #{first_server[:name]} 部署完成")

        # Wait for first server to be ready
        if wait_for_server_ready(first_server)
          @logger.success("第一个服务器节点 #{first_server[:name]} 已就绪")
        else
          @logger.error("第一个服务器节点 #{first_server[:name]} 启动失败")
          return false
        end
      else
        @logger.error("第一个服务器节点 #{first_server[:name]} 部署失败")
        return false
      end

      # Deploy additional server nodes if any
      if server_nodes.length > 1
        additional_servers = server_nodes[1..-1]

        additional_servers.each_with_index do |node, index|
          @logger.step(index + 2, server_nodes.length, "部署额外服务器节点 #{node[:name]}")

          if deploy_additional_server(node, first_server)
            success_count += 1
            @logger.success("服务器节点 #{node[:name]} 部署完成")
          else
            failed_nodes << node[:name]
            @logger.error("服务器节点 #{node[:name]} 部署失败")
          end
        end
      end

      # Summary
      if failed_nodes.empty?
        @logger.success("🎉 所有 #{server_nodes.length} 个服务器节点部署完成！")
        display_cluster_info(server_nodes)
        true
      else
        @logger.error("❌ #{failed_nodes.length} 个服务器节点部署失败: #{failed_nodes.join(', ')}")
        @logger.info("✅ #{success_count} 个服务器节点部署成功")
        false
      end
    end

    # Deploy RKE2 server on a single node
    #
    # @param node [Hash] Server node configuration
    # @param is_first [Boolean] Whether this is the first server node
    # @return [Boolean] True if deployment successful
    def deploy_server_node(node, is_first: true)
      @logger.time("服务器节点 #{node[:name]} 部署") do
        # Test connectivity first
        unless test_node_connectivity(node)
          @logger.error("服务器节点 #{node[:name]} 连接测试失败")
          return false
        end

        if is_first
          deploy_first_server(node)
        else
          # For additional servers, we need the first server info
          server_nodes = extract_server_nodes
          first_server = server_nodes.first
          deploy_additional_server(node, first_server)
        end
      end
    rescue StandardError => e
      @logger.error("服务器节点 #{node[:name]} 部署异常: #{e.message}")
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

      raise ArgumentError, '配置文件中缺少 nodes 配置或格式错误' unless @config['nodes']&.is_a?(Array)
      raise ArgumentError, '配置文件中没有定义任何节点' if @config['nodes'].empty?

      # Validate token
      @logger.warn('配置文件中未设置 token，将使用默认 token') if @config['token'].nil? || @config['token'].to_s.strip.empty?

      @logger.info('配置文件验证通过')
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

    # Deploy the first RKE2 server node (cluster initialization)
    #
    # @param node [Hash] Server node configuration
    # @return [Boolean] True if deployment successful
    def deploy_first_server(node)
      @logger.loading("部署第一个服务器节点 #{node[:name]}")

      # Generate and upload RKE2 server installation script
      script_content = generate_first_server_script(node)
      script_path = "/tmp/rke2_server_first_#{node[:name]}_#{Time.now.to_i}.sh"

      # Upload script
      @logger.loading("上传 RKE2 服务器安装脚本到 #{node[:name]}")
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

      # Execute installation script with progress reporting
      @logger.loading('执行 RKE2 服务器安装脚本')
      exec_result = @helper.ssh_exec_long_running(
        node[:ip],
        node[:username],
        "chmod +x #{script_path} && #{script_path}",
        node[:ssh_key],
        timeout: 600, # 30 minutes timeout for installation
        progress_interval: 20 # Show progress every 20 seconds
      )

      # Cleanup script
      # @helper.ssh_exec(node[:ip], node[:username], "rm -f #{script_path}", node[:ssh_key], skip_sudo: false)

      if exec_result[:success]
        @logger.info('RKE2 服务器安装脚本执行完成', {
                       node: node[:name],
                       output_length: exec_result[:output].length
                     })

        # Log script output if in debug mode
        if @logger.logger.level <= ::Logger::DEBUG
          safe_output = safe_encode_utf8(exec_result[:output])
          @logger.debug("RKE2 服务器安装脚本输出:\n#{safe_output}")
        end

        true
      else
        @logger.error('RKE2 服务器安装脚本执行失败', {
                        node: node[:name],
                        error: exec_result[:error],
                        exit_code: exec_result[:exit_code]
                      })
        false
      end
    end

    # Deploy additional RKE2 server nodes (join existing cluster)
    #
    # @param node [Hash] Server node configuration
    # @param first_server [Hash] First server node configuration
    # @return [Boolean] True if deployment successful
    def deploy_additional_server(node, first_server)
      @logger.loading("部署额外服务器节点 #{node[:name]}")

      # Generate and upload RKE2 server join script
      script_content = generate_additional_server_script(node, first_server)
      script_path = "/tmp/rke2_server_join_#{node[:name]}_#{Time.now.to_i}.sh"

      # Upload script
      @logger.loading("上传 RKE2 服务器加入脚本到 #{node[:name]}")
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

      # Execute join script with progress reporting
      @logger.loading('执行 RKE2 服务器加入脚本')
      exec_result = @helper.ssh_exec_long_running(
        node[:ip],
        node[:username],
        "chmod +x #{script_path} && #{script_path}",
        node[:ssh_key],
        timeout: 600, # 30 minutes timeout for installation
        progress_interval: 20 # Show progress every 20 seconds
      )

      # Cleanup script
      @helper.ssh_exec(node[:ip], node[:username], "rm -f #{script_path}", node[:ssh_key], skip_sudo: false)

      if exec_result[:success]
        @logger.info('RKE2 服务器加入脚本执行完成', {
                       node: node[:name],
                       output_length: exec_result[:output].length
                     })

        # Log script output if in debug mode
        if @logger.logger.level <= ::Logger::DEBUG
          safe_output = safe_encode_utf8(exec_result[:output])
          @logger.debug("RKE2 服务器加入脚本输出:\n#{safe_output}")
        end

        true
      else
        @logger.error('RKE2 服务器加入脚本执行失败', {
                        node: node[:name],
                        error: exec_result[:error],
                        exit_code: exec_result[:exit_code]
                      })
        false
      end
    end

    # Wait for server to be ready
    #
    # @param node [Hash] Server node configuration
    # @param timeout [Integer] Maximum wait time in seconds
    # @return [Boolean] True if server is ready
    def wait_for_server_ready(node, timeout: 600)
      @logger.info("等待服务器节点 #{node[:name]} 就绪...")

      start_time = Time.now
      service_ready = false
      kubectl_ready = false

      while (Time.now - start_time) < timeout
        # Check if RKE2 server is running
        unless service_ready
          result = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'systemctl is-active rke2-server',
            node[:ssh_key],
            skip_sudo: false
          )

          if result[:success] && result[:output].strip == 'active'
            @logger.info('RKE2 服务器服务已启动')
            service_ready = true
          else
            @logger.debug("等待 RKE2 服务器启动... (#{(Time.now - start_time).to_i}s)")
            sleep 5
            next
          end
        end

        # Once service is ready, check kubectl access
        if service_ready && !kubectl_ready
          # First check if system kubeconfig exists
          system_config_check = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'ls -la /etc/rancher/rke2/rke2.yaml 2>/dev/null || echo "system config not found"',
            node[:ssh_key],
            skip_sudo: false
          )

          if @logger.logger.level <= ::Logger::DEBUG
            safe_system_output = safe_encode_utf8(system_config_check[:output])
            @logger.debug("系统 kubeconfig 状态: #{safe_system_output}")
          end

          # Check if user kubeconfig exists
          config_check = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'sudo ls -la /root/.kube/config 2>/dev/null || echo "user config not found"',
            node[:ssh_key],
            skip_sudo: false
          )

          if @logger.logger.level <= ::Logger::DEBUG
            safe_user_output = safe_encode_utf8(config_check[:output])
            @logger.debug("用户 kubeconfig 状态: #{safe_user_output}")
          end

          # Try to create user kubeconfig if system config exists but user config doesn't
          if system_config_check[:success] &&
             !system_config_check[:output].include?('system config not found') &&
             config_check[:output].include?('user config not found')

            @logger.info('尝试手动创建用户 kubeconfig...')
            create_config_result = @helper.ssh_exec(
              node[:ip],
              node[:username],
              'sudo mkdir -p /root/.kube && sudo cp /etc/rancher/rke2/rke2.yaml /root/.kube/config && sudo chown root:root /root/.kube/config && chmod 600 /root/.kube/config',
              node[:ssh_key]
            )

            if create_config_result[:success]
              @logger.info('用户 kubeconfig 创建成功')
            else
              @logger.debug("用户 kubeconfig 创建失败: #{safe_encode_utf8(create_config_result[:error].to_s)}")
            end
          end

          # Final check if user kubeconfig is ready
          final_config_check = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'sudo test -f /root/.kube/config && sudo test -r /root/.kube/config',
            node[:ssh_key],
            skip_sudo: false
          )

          unless final_config_check[:success]
            @logger.debug("等待用户 kubeconfig 文件生成和权限设置... (#{(Time.now - start_time).to_i}s)")
            sleep 5
            next
          end

          # Test kubectl access - check for Ready nodes
          @logger.debug('测试 kubectl 访问和节点状态...')
          kubectl_result = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'export PATH=$PATH:/var/lib/rancher/rke2/bin && kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes --no-headers 2>/dev/null | grep -c Ready',
            node[:ssh_key],
            skip_sudo: false
          )

          ready_count = kubectl_result[:output].strip.to_i
          if kubectl_result[:success] && ready_count > 0
            @logger.success("服务器节点 #{node[:name]} 已就绪 (发现 #{ready_count} 个 Ready 节点)")
            return true
          else
            @logger.debug("kubectl 测试结果: #{safe_encode_utf8(kubectl_result[:output].to_s)}")
          end

          # Additional service health check
          service_health = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'systemctl is-active rke2-server && journalctl -u rke2-server --since "2 minutes ago" | grep -i "error\\|failed\\|panic" | wc -l',
            node[:ssh_key],
            skip_sudo: false
          )

          if service_health[:success]
            lines = service_health[:output].strip.split("\n")
            if lines[0] == 'active' && lines[1].to_i < 5 # Less than 5 error lines in last 2 minutes
              @logger.warn('Kubernetes API 暂时不可访问，但 RKE2 服务运行正常')
              @logger.info('继续等待 API 服务器启动...')
            end
          end

          @logger.debug("等待 Kubernetes API 服务器就绪... (#{(Time.now - start_time).to_i}s)")

        end

        sleep 10
      end

      @logger.warn("在 #{timeout} 秒内 kubectl 未完全就绪，执行最终验证...")

      # Final comprehensive check
      final_checks = @helper.ssh_exec(
        node[:ip],
        node[:username],
        [
          'echo "=== 服务状态 ==="',
          'systemctl is-active rke2-server',
          'echo "=== 进程检查 ==="',
          'pgrep -f rke2-server | wc -l',
          'echo "=== 端口检查 ==="',
          'netstat -tln | grep -E "(6443|9345)" | wc -l',
          'echo "=== Kubeconfig 检查 ==="',
          'test -f /etc/rancher/rke2/rke2.yaml && echo "system-config-exists" || echo "system-config-missing"',
          'echo "=== 容器运行时检查 ==="',
          'crictl ps 2>/dev/null | grep -v "CONTAINER ID" | wc -l 2>/dev/null || echo "0"',
          'echo "=== 最近错误检查 ==="',
          'journalctl -u rke2-server --since "5 minutes ago" | grep -i "panic\\|fatal" | wc -l'
        ].join(' && '),
        node[:ssh_key],
        skip_sudo: false
      )

      if final_checks[:success]
        lines = final_checks[:output].strip.split("\n")
        safe_output = safe_encode_utf8(final_checks[:output])
        @logger.debug("最终检查结果:\n#{safe_output}")

        # Parse results
        service_active = lines[1] == 'active'
        process_count = lines[3].to_i
        port_count = lines[5].to_i
        config_exists = lines[7] == 'system-config-exists'
        container_count = lines[9].to_i
        error_count = lines[11].to_i

        @logger.info('最终状态摘要:')
        @logger.info("  服务状态: #{service_active ? '✅ 运行中' : '❌ 未运行'}")
        @logger.info("  进程数量: #{process_count}")
        @logger.info("  端口监听: #{port_count} 个端口")
        @logger.info("  配置文件: #{config_exists ? '✅ 存在' : '❌ 缺失'}")
        @logger.info("  容器数量: #{container_count}")
        @logger.info("  近期错误: #{error_count}")

        # Final kubectl test for validation
        kubectl_ok = false
        if service_active && config_exists
          # Test kubectl access and node ready status
          kubectl_check = @helper.ssh_exec(
            node[:ip],
            node[:username],
            'export PATH=$PATH:/var/lib/rancher/rke2/bin && kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes --no-headers 2>/dev/null | grep -c Ready',
            node[:ssh_key],
            skip_sudo: false
          )

          ready_count = kubectl_check[:output].strip.to_i
          kubectl_ok = kubectl_check[:success] && ready_count > 0
          @logger.info("  kubectl 访问: #{kubectl_ok ? "✅ 正常 (#{ready_count} 个 Ready 节点)" : '❌ 异常'}")
        end

        # Basic success criteria: service running + config exists + minimal errors
        if service_active && config_exists && error_count < 10
          if kubectl_ok
            @logger.success('✅ RKE2 集群部署成功！kubectl 访问正常')
            @logger.info('💡 可以使用 kubectl 命令管理集群')
          else
            @logger.warn('⚠️ RKE2 服务运行正常，但 kubectl 访问可能需要更多时间')
            @logger.success('认定部署基本成功，建议稍后验证集群状态')
          end
          return true
        end
      end

      @logger.error("服务器节点 #{node[:name]} 部署验证失败")
      false
    end

    # Generate installation script for the first server node
    #
    # @param node [Hash] Server node configuration
    # @return [String] Installation script content
    def generate_first_server_script(node)
      token = @config['token'] || 'rke2Secret123456'
      loadbalancer_ip = @config['loadbalancer_ip']

      # Determine server URL for cluster setup
      if loadbalancer_ip
        "https://#{loadbalancer_ip}:9345"
      else
        # For single master or first master in HA setup
        "https://#{node[:ip]}:9345"
      end

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

        log_info "🚀 开始安装 RKE2 Server 在节点 #{node[:name]}..."

        # Get system information
        log_info "📊 系统信息:"
        echo "  主机名: $(hostname)"
        echo "  系统版本: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
        echo "  内核版本: $(uname -r)"
        echo "  节点IP: #{node[:ip]}"
        echo "  集群Token: #{token}"

        # Create RKE2 directories
        log_info "📁 创建 RKE2 目录..."
        mkdir -p /etc/rancher/rke2
        mkdir -p /var/lib/rancher/rke2

        # Create RKE2 server configuration
        log_info "🔧 生成 RKE2 服务器配置..."
        cat > /etc/rancher/rke2/config.yaml << 'EOF'
        # RKE2 Server Configuration
        # Node name
        node-name: #{node[:name]}

        # Server token
        token: #{token}

        # Network configuration
        cluster-cidr: 10.42.0.0/16
        service-cidr: 10.43.0.0/16
        cluster-dns: 10.43.0.10

        # etcd configuration
        etcd-expose-metrics: true

        # API server configuration
        kube-apiserver-arg:
          - audit-log-maxage=30
          - audit-log-maxbackup=10
          - audit-log-maxsize=100
          - audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log

        # kubelet configuration
        kubelet-arg:
          - max-pods=110

        # Container runtime
        cni: canal

        #{loadbalancer_ip ? "# Load balancer configuration\ntls-san:\n  - #{loadbalancer_ip}" : '# Single master setup'}

        # Disable components (optional)
        # disable: rke2-metrics-server

        # TLS configuration
        tls-san:
          - #{node[:ip]}
          - #{node[:name]}
          - localhost
          - 127.0.0.1
        #{loadbalancer_ip ? "  - #{loadbalancer_ip}" : ''}

        EOF

        log_success "RKE2 服务器配置已创建"

        # Download and install RKE2
        log_info "📦 下载并安装 RKE2..."
        curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="server" sh -

        if [ $? -eq 0 ]; then
            log_success "RKE2 下载安装完成"
                else
            log_error "RKE2 下载安装失败"
            exit 1
                fi

        # Enable and start RKE2 server service
        log_info "🚀 启动 RKE2 服务器服务..."
        systemctl enable rke2-server.service
        systemctl restart rke2-server.service

        # Wait for service to start
        log_info "⏳ 等待 RKE2 服务器启动..."
        sleep 30

        # Check service status
        if systemctl is-active --quiet rke2-server; then
            log_success "RKE2 服务器服务已成功启动"
                else
            log_error "RKE2 服务器服务启动失败"
            systemctl status rke2-server
            journalctl -u rke2-server --no-pager -l
            exit 1
                fi

        # Set up kubectl access
        log_info "🔧 配置 kubectl 访问..."
        setup_kubectl_access() {
            # Wait for kubeconfig to be generated
            for i in {1..30}; do
                if [ -f /etc/rancher/rke2/rke2.yaml ]; then
                    log_info "发现系统 kubeconfig 文件"
                    break
                elif [ \$i -eq 30 ]; then
                    log_error "系统 kubeconfig 文件未生成"
                    return 1
                else
                    echo "  等待系统 kubeconfig 文件生成... (\$i/30)"
                    sleep 5
                fi
            done


            # Create user kubectl config
            mkdir -p /root/.kube
            if cp /etc/rancher/rke2/rke2.yaml /root/.kube/config; then
                chmod 600 /root/.kube/config
                log_success "用户 kubeconfig 已创建"
                return 0
            else
                log_error "用户 kubeconfig 创建失败"
                return 1
            fi
        }
        setup_kubectl_access

        # Add RKE2 binaries to PATH
        echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> ~/.bashrc
        export PATH=$PATH:/var/lib/rancher/rke2/bin

        # Create symlink for kubectl
        if [ ! -f /usr/local/bin/kubectl ]; then
            ln -s /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
                fi

        # Wait for cluster to be ready
        log_info "⏳ 等待集群就绪..."
        for i in {1..30}; do
            if /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes >/dev/null 2>&1; then
                log_success "集群已就绪"
                break
            fi
            echo "  等待集群就绪... ($i/30)"
            sleep 10
        done

        # Display cluster information
        log_info "📊 集群状态信息:"
        echo "  RKE2 版本: $(/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version --client=true -o yaml 2>/dev/null | grep gitVersion | cut -d: -f2 | tr -d ' \"' || echo 'Unknown')"
        echo "  节点状态:"
        /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide

        # Get node token for additional servers
        log_info "🔑 获取节点 Token..."
        NODE_TOKEN=$(cat /var/lib/rancher/rke2/server/node-token)
        echo "  节点 Token: $NODE_TOKEN"

        # Configure firewall
        log_info "🔥 配置防火墙..."
        configure_firewall() {
            # Open required ports for RKE2 server
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 2379/tcp   # etcd client requests
                ufw allow 2380/tcp   # etcd peer communication
                ufw allow 6443/tcp   # Kubernetes API server
                ufw allow 9345/tcp   # RKE2 supervisor API
                ufw allow 10250/tcp  # kubelet API
                ufw allow 10251/tcp  # kube-scheduler
                ufw allow 10252/tcp  # kube-controller-manager
                ufw allow 10254/tcp  # Ingress controller
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=2379/tcp
                firewall-cmd --permanent --add-port=2380/tcp
                firewall-cmd --permanent --add-port=6443/tcp
                firewall-cmd --permanent --add-port=9345/tcp
                firewall-cmd --permanent --add-port=10250/tcp
                firewall-cmd --permanent --add-port=10251/tcp
                firewall-cmd --permanent --add-port=10252/tcp
                firewall-cmd --permanent --add-port=10254/tcp
                firewall-cmd --reload
            elif command -v iptables >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 2379 -j ACCEPT
                iptables -A INPUT -p tcp --dport 2380 -j ACCEPT
                iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
                iptables -A INPUT -p tcp --dport 9345 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10251 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10252 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10254 -j ACCEPT
            fi
        }
        configure_firewall
        log_success "防火墙规则已配置"

        log_success "🎉 RKE2 服务器节点 #{node[:name]} 安装完成！"

        log_info "📈 安装摘要:"
        echo "  - ✅ RKE2 服务器已安装并启动"
        echo "  - ✅ kubectl 已配置"
        echo "  - ✅ 防火墙规则已设置"
        echo "  - ✅ 集群已初始化"

        log_info "🌐 访问信息:"
        echo "  Kubernetes API: https://#{node[:ip]}:6443"
        echo "  RKE2 注册服务: https://#{node[:ip]}:9345"
        #{loadbalancer_ip ? "echo \"  负载均衡地址: https://#{loadbalancer_ip}:6443\"" : ''}
        echo "  节点 Token: $NODE_TOKEN"

        log_info "💡 下一步操作:"
        echo "  1. 复制 kubeconfig 文件到本地: scp #{node[:username]}@#{node[:ip]}:/root/.kube/config /root/.kube/config"
        echo "  2. 安装额外的 server 节点 (如果需要 HA)"
        echo "  3. 安装 agent 节点"
        echo "  4. 配置负载均衡器 (如果使用 HA)"

        exit 0
      SCRIPT
    end

    # Generate installation script for additional server nodes
    #
    # @param node [Hash] Server node configuration
    # @param first_server [Hash] First server node configuration
    # @return [String] Installation script content
    def generate_additional_server_script(node, first_server)
      token = @config['token'] || 'rke2Secret123456'
      loadbalancer_ip = @config['loadbalancer_ip']

      # Determine server URL for joining
      server_url = if loadbalancer_ip
                     "https://#{loadbalancer_ip}:9345"
                   else
                     "https://#{first_server[:ip]}:9345"
                   end

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

        log_info "🚀 开始安装额外 RKE2 Server 在节点 #{node[:name]}..."

        # Get system information
        log_info "📊 系统信息:"
        echo "  主机名: $(hostname)"
        echo "  系统版本: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
        echo "  内核版本: $(uname -r)"
        echo "  节点IP: #{node[:ip]}"
        echo "  加入服务器: #{server_url}"

        # Create RKE2 directories
        log_info "📁 创建 RKE2 目录..."
        mkdir -p /etc/rancher/rke2
        mkdir -p /var/lib/rancher/rke2

        # Create RKE2 server configuration for additional server
        log_info "🔧 生成 RKE2 服务器配置..."
        cat > /etc/rancher/rke2/config.yaml << 'EOF'
        # RKE2 Additional Server Configuration
        # Server to join
        server: #{server_url}

        # Node name
        node-name: #{node[:name]}

        # Server token
        token: #{token}

        # TLS configuration
        tls-san:
          - #{node[:ip]}
          - #{node[:name]}
          - localhost
          - 127.0.0.1
        #{loadbalancer_ip ? "  - #{loadbalancer_ip}" : ''}

        EOF

        log_success "RKE2 服务器配置已创建"

        # Download and install RKE2
        log_info "📦 下载并安装 RKE2..."
        curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="server" sh -

        if [ $? -eq 0 ]; then
            log_success "RKE2 下载安装完成"
                else
            log_error "RKE2 下载安装失败"
            exit 1
                fi

        # Enable and start RKE2 server service
        log_info "🚀 启动 RKE2 服务器服务..."
        systemctl enable rke2-server.service
        systemctl restart rke2-server.service

        # Wait for service to start
        log_info "⏳ 等待 RKE2 服务器启动..."
        sleep 30

        # Check service status
        if systemctl is-active --quiet rke2-server; then
            log_success "RKE2 服务器服务已成功启动"
                else
            log_error "RKE2 服务器服务启动失败"
            systemctl status rke2-server
            journalctl -u rke2-server --no-pager -l
            exit 1
                fi

        # Set up kubectl access
        log_info "🔧 配置 kubectl 访问..."
        setup_kubectl_access() {
            # Wait for kubeconfig to be generated
            for i in {1..30}; do
                if [ -f /etc/rancher/rke2/rke2.yaml ]; then
                    log_info "发现系统 kubeconfig 文件"
                    break
                elif [ \$i -eq 30 ]; then
                    log_error "系统 kubeconfig 文件未生成"
                    return 1
                else
                    echo "  等待系统 kubeconfig 文件生成... (\$i/30)"
                    sleep 5
                fi
            done


            # Create user kubectl config
            mkdir -p /root/.kube
            if cp /etc/rancher/rke2/rke2.yaml /root/.kube/config; then
                chmod 600 /root/.kube/config
                log_success "用户 kubeconfig 已创建"
                return 0
            else
                log_error "用户 kubeconfig 创建失败"
                return 1
            fi
        }
        setup_kubectl_access

        # Add RKE2 binaries to PATH
        echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> ~/.bashrc
        export PATH=$PATH:/var/lib/rancher/rke2/bin

        # Create symlink for kubectl
        if [ ! -f /usr/local/bin/kubectl ]; then
            ln -s /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
                fi

        # Wait for node to join cluster
        log_info "⏳ 等待节点加入集群..."
        for i in {1..30}; do
            if /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes | grep -q #{node[:name]}; then
                log_success "节点已成功加入集群"
                break
            fi
            echo "  等待节点加入集群... ($i/30)"
            sleep 10
        done

        # Configure firewall
        log_info "🔥 配置防火墙..."
        configure_firewall() {
            # Open required ports for RKE2 server
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 2379/tcp   # etcd client requests
                ufw allow 2380/tcp   # etcd peer communication
                ufw allow 6443/tcp   # Kubernetes API server
                ufw allow 9345/tcp   # RKE2 supervisor API
                ufw allow 10250/tcp  # kubelet API
                ufw allow 10251/tcp  # kube-scheduler
                ufw allow 10252/tcp  # kube-controller-manager
                ufw allow 10254/tcp  # Ingress controller
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=2379/tcp
                firewall-cmd --permanent --add-port=2380/tcp
                firewall-cmd --permanent --add-port=6443/tcp
                firewall-cmd --permanent --add-port=9345/tcp
                firewall-cmd --permanent --add-port=10250/tcp
                firewall-cmd --permanent --add-port=10251/tcp
                firewall-cmd --permanent --add-port=10252/tcp
                firewall-cmd --permanent --add-port=10254/tcp
                firewall-cmd --reload
            elif command -v iptables >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 2379 -j ACCEPT
                iptables -A INPUT -p tcp --dport 2380 -j ACCEPT
                iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
                iptables -A INPUT -p tcp --dport 9345 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10251 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10252 -j ACCEPT
                iptables -A INPUT -p tcp --dport 10254 -j ACCEPT
            fi
        }
        configure_firewall
        log_success "防火墙规则已配置"

        # Display cluster information
        log_info "📊 集群状态信息:"
        /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide

        log_success "🎉 RKE2 额外服务器节点 #{node[:name]} 安装完成！"

        log_info "📈 安装摘要:"
        echo "  - ✅ RKE2 服务器已安装并启动"
        echo "  - ✅ 节点已加入集群"
        echo "  - ✅ kubectl 已配置"
        echo "  - ✅ 防火墙规则已设置"

        exit 0
      SCRIPT
    end

    # Display cluster information after deployment
    #
    # @param server_nodes [Array<Hash>] Array of server node configurations
    def display_cluster_info(server_nodes)
      loadbalancer_ip = @config['loadbalancer_ip']
      token = @config['token'] || 'rke2Secret123456'

      @logger.info("\n🌐 RKE2 集群部署完成！")

      puts "\n📋 集群信息:"
      puts "  集群节点数: #{server_nodes.length}"
      puts "  集群 Token: #{token}"

      if loadbalancer_ip
        puts "  负载均衡地址: #{loadbalancer_ip}"
        puts "  Kubernetes API: https://#{loadbalancer_ip}:6443"
        puts "  RKE2 注册服务: https://#{loadbalancer_ip}:9345"
      else
        first_server = server_nodes.first
        puts "  主服务器地址: #{first_server[:ip]}"
        puts "  Kubernetes API: https://#{first_server[:ip]}:6443"
        puts "  RKE2 注册服务: https://#{first_server[:ip]}:9345"
      end

      puts "\n🖥️  服务器节点列表:"
      server_nodes.each do |node|
        puts "  - #{node[:name]}: #{node[:ip]}"
      end

      puts "\n💡 下一步操作:"
      puts '  1. 获取 kubeconfig 文件:'
      first_server = server_nodes.first
      puts "     scp #{first_server[:username]}@#{first_server[:ip]}:/etc/rancher/rke2/rke2.yaml /root/.kube/config"
      puts "     sed -i 's/127.0.0.1/#{loadbalancer_ip || first_server[:ip]}/g' /root/.kube/config"
      puts ''
      puts '  2. 验证集群状态:'
      puts '     kubectl get nodes'
      puts '     kubectl get pods -A'
      puts ''
      puts '  3. 部署 Agent 节点 (如果需要):'
      puts "     使用 Token: #{token}"
      puts "     连接地址: https://#{loadbalancer_ip || first_server[:ip]}:9345"
    end

    # Class methods for easy access
    class << self
      # Deploy RKE2 server on all server nodes
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if all server nodes deployed successfully
      def deploy_all(config_file = 'config.yml', logger: nil)
        server = new(config_file, logger: logger)
        server.deploy_all_servers
      end

      # Deploy RKE2 server on a specific node
      #
      # @param node_name [String] Name of the server node to deploy
      # @param config_file [String] Path to configuration file
      # @param is_first [Boolean] Whether this is the first server node
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if server node deployed successfully
      def deploy_node(node_name, config_file = 'config.yml', is_first: true, logger: nil)
        server = new(config_file, logger: logger)
        server.load_configuration

        server_nodes = server.extract_server_nodes
        target_node = server_nodes.find { |node| node[:name] == node_name }

        unless target_node
          server.logger.error("服务器节点 '#{node_name}' 在配置文件中未找到")
          return false
        end

        server.logger.deploy("🚀 开始部署服务器节点 #{node_name}")
        result = server.deploy_server_node(target_node, is_first: is_first)

        if result
          server.logger.success("🎉 服务器节点 #{node_name} 部署完成！")
        else
          server.logger.error("❌ 服务器节点 #{node_name} 部署失败")
        end

        result
      end
    end
  end
end

# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require_relative 'config'
require_relative 'helper'
require_relative 'logger'

module RKE2
  # RKE2 Agent deployment class for worker nodes
  class Agent
    include RKE2::Config

    attr_reader :logger, :helper, :config

    # Initialize agent with configuration
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @helper = RKE2::Helper.new(logger: @logger)
      @config_file = config_file
      @config = nil
    end

    # Deploy RKE2 agent on all agent nodes
    #
    # @return [Boolean] True if all agent nodes deployed successfully
    def deploy_all_agents
      @logger.deploy('🚀 开始部署 RKE2 Agent 节点')

      load_configuration
      validate_configuration

      agent_nodes = extract_agent_nodes

      if agent_nodes.empty?
        @logger.error('配置文件中未找到代理节点 (role: agent)')
        return false
      end

      @logger.info("发现 #{agent_nodes.length} 个代理节点需要部署")

      # Verify HAProxy is available before deploying agents
      unless verify_haproxy_connectivity
        @logger.error('无法连接到负载均衡器，请确保 HAProxy 已正确配置并运行')
        return false
      end

      success_count = 0
      failed_nodes = []

      agent_nodes.each_with_index do |node, index|
        @logger.step(index + 1, agent_nodes.length, "部署代理节点 #{node[:name]}")

        if deploy_agent_node(node)
          success_count += 1
          @logger.success("代理节点 #{node[:name]} 部署完成")
        else
          failed_nodes << node[:name]
          @logger.error("代理节点 #{node[:name]} 部署失败")
        end
      end

      # Summary
      if failed_nodes.empty?
        @logger.success("🎉 所有 #{agent_nodes.length} 个代理节点部署完成！")
        display_cluster_info(agent_nodes)
        true
      else
        @logger.error("❌ #{failed_nodes.length} 个代理节点部署失败: #{failed_nodes.join(', ')}")
        @logger.info("✅ #{success_count} 个代理节点部署成功")
        false
      end
    end

    # Deploy RKE2 agent on a single node
    #
    # @param node [Hash] Agent node configuration
    # @return [Boolean] True if deployment successful
    def deploy_single_agent(node)
      @logger.time("代理节点 #{node[:name]} 部署") do
        # Test connectivity first
        unless test_node_connectivity(node)
          @logger.error("代理节点 #{node[:name]} 连接测试失败")
          return false
        end

        # Verify HAProxy connectivity
        unless verify_haproxy_connectivity
          @logger.error('无法连接到负载均衡器，请确保 HAProxy 已正确配置并运行')
          return false
        end

        deploy_agent_node(node)
      end
    rescue StandardError => e
      @logger.error("代理节点 #{node[:name]} 部署异常: #{e.message}")
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

      # Validate loadbalancer_ip for agent deployment
      if @config['loadbalancer_ip'].nil? || @config['loadbalancer_ip'].to_s.strip.empty?
        @logger.error('配置文件中缺少 loadbalancer_ip，agent 节点必须通过负载均衡器连接')
        raise ArgumentError, '配置文件中缺少 loadbalancer_ip 配置'
      end

      # Validate token
      @logger.warn('配置文件中未设置 token，将使用默认 token') if @config['token'].nil? || @config['token'].to_s.strip.empty?

      @logger.info('配置文件验证通过')
    end

    # Extract agent nodes from configuration
    #
    # @return [Array<Hash>] Array of agent node configurations
    def extract_agent_nodes
      @config['nodes'].select { |node| node['role'] == 'agent' }.map do |node|
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

    # Verify HAProxy connectivity
    #
    # @return [Boolean] True if HAProxy is accessible
    def verify_haproxy_connectivity
      loadbalancer_ip = @config['loadbalancer_ip']
      @logger.debug("验证负载均衡器连接: #{loadbalancer_ip}")

      # Test RKE2 registration service port (9345)
      unless @helper.host_reachable?(loadbalancer_ip, 9345, 10)
        @logger.error("负载均衡器 #{loadbalancer_ip}:9345 (RKE2 注册服务) 不可达")
        return false
      end

      # Test Kubernetes API port (6443)
      unless @helper.host_reachable?(loadbalancer_ip, 6443, 10)
        @logger.warn("负载均衡器 #{loadbalancer_ip}:6443 (Kubernetes API) 不可达，但这可能是正常的")
      end

      @logger.success("负载均衡器 #{loadbalancer_ip} 连接验证通过")
      true
    end

    # Deploy RKE2 agent on a single node
    #
    # @param node [Hash] Agent node configuration
    # @return [Boolean] True if deployment successful
    def deploy_agent_node(node)
      @logger.loading("部署代理节点 #{node[:name]}")

      # Generate and upload RKE2 agent installation script
      script_content = generate_agent_script(node)
      script_path = "/tmp/rke2_agent_#{node[:name]}_#{Time.now.to_i}.sh"

      # Upload script
      @logger.loading("上传 RKE2 代理安装脚本到 #{node[:name]}")
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

      # Execute installation script
      @logger.loading('执行 RKE2 代理安装脚本')
      exec_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        "chmod +x #{script_path} && #{script_path}",
        node[:ssh_key],
        timeout: 600 # 10 minutes timeout for installation
      )

      # Cleanup script
      # @helper.ssh_exec(node[:ip], node[:username], "rm -f #{script_path}", node[:ssh_key], skip_sudo: false)

      if exec_result[:success]
        @logger.info('RKE2 代理安装脚本执行完成', {
                       node: node[:name],
                       output_length: exec_result[:output].length
                     })

        # Log script output if in debug mode
        if @logger.logger.level <= ::Logger::DEBUG
          safe_output = safe_encode_utf8(exec_result[:output])
          @logger.debug("RKE2 代理安装脚本输出:\n#{safe_output}")
        end

        # Wait for agent to join cluster
        if wait_for_agent_ready(node)
          @logger.success("代理节点 #{node[:name]} 已加入集群")
          true
        else
          @logger.error("代理节点 #{node[:name]} 未能正确加入集群")
          false
        end
      else
        safe_error = safe_encode_utf8(exec_result[:error].to_s)
        @logger.error('RKE2 代理安装脚本执行失败', {
                        node: node[:name],
                        error: safe_error,
                        exit_code: exec_result[:exit_code]
                      })
        false
      end
    end

    # Wait for agent to be ready and join cluster
    #
    # @param node [Hash] Agent node configuration
    # @param timeout [Integer] Maximum wait time in seconds
    # @return [Boolean] True if agent is ready
    def wait_for_agent_ready(node, timeout: 300)
      @logger.info("等待代理节点 #{node[:name]} 加入集群...")

      start_time = Time.now
      while (Time.now - start_time) < timeout
        # Check if RKE2 agent is running
        result = @helper.ssh_exec(
          node[:ip],
          node[:username],
          'systemctl is-active rke2-agent',
          node[:ssh_key],
          skip_sudo: false
        )

        if result[:success] && result[:output].strip == 'active'
          @logger.success("代理节点 #{node[:name]} 服务已启动")
          return true
        end

        @logger.debug("等待代理节点 #{node[:name]} 服务启动... (#{(Time.now - start_time).to_i}s)")
        sleep 10
      end

      @logger.error("代理节点 #{node[:name]} 在 #{timeout} 秒内未启动")
      false
    end

    # Generate installation script for agent node
    #
    # @param node [Hash] Agent node configuration
    # @return [String] Installation script content
    def generate_agent_script(node)
      token = @config['token'] || 'rke2Secret123456'
      loadbalancer_ip = @config['loadbalancer_ip']
      server_url = "https://#{loadbalancer_ip}:9345"

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

        log_info "🚀 开始安装 RKE2 Agent 在节点 #{node[:name]}..."

        # Get system information
        log_info "📊 系统信息:"
        echo "  主机名: $(hostname)"
        echo "  系统版本: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s)"
        echo "  内核版本: $(uname -r)"
        echo "  节点IP: #{node[:ip]}"
        echo "  连接服务器: #{server_url}"
        echo "  集群Token: #{token}"

        # Test connectivity to load balancer
        log_info "🔗 测试负载均衡器连接..."
        # Use timeout + bash TCP test (more compatible than nc)
        if ! timeout 10 bash -c "exec 3<>/dev/tcp/#{loadbalancer_ip}/9345" 2>/dev/null; then
            log_error "无法连接到负载均衡器 #{loadbalancer_ip}:9345"
            log_error "请确保:"
            echo "  1. 负载均衡器 HAProxy 服务正在运行"
            echo "  2. RKE2 服务器节点已部署并运行"
            echo "  3. 网络连接正常"
            echo "  4. 防火墙允许端口 9345 通信"
            exit 1
        fi
        log_success "负载均衡器连接测试通过"

        # Create RKE2 directories
        log_info "📁 创建 RKE2 目录..."
        mkdir -p /etc/rancher/rke2
        mkdir -p /var/lib/rancher/rke2

        # Create RKE2 agent configuration
        log_info "🔧 生成 RKE2 代理配置..."
        cat > /etc/rancher/rke2/config.yaml << 'EOF'
        # RKE2 Agent Configuration
        # Server to connect to (through load balancer)
        server: #{server_url}

        # Node name
        node-name: #{node[:name]}

        # Cluster token
        token: #{token}

        # kubelet configuration
        kubelet-arg:
          - max-pods=110

        # Node labels (optional)
        node-label:
          - node-type=worker
          - environment=production

        # Node taints (optional - uncomment if needed)
        # node-taint:
        #   - dedicated=worker:NoSchedule

        EOF

        log_success "RKE2 代理配置已创建"

        # Download and install RKE2
        log_info "📦 下载并安装 RKE2..."
        curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -

        if [ $? -eq 0 ]; then
            log_success "RKE2 下载安装完成"
        else
            log_error "RKE2 下载安装失败"
            exit 1
        fi

        # Enable and start RKE2 agent service
        log_info "🚀 启动 RKE2 代理服务..."
        systemctl enable rke2-agent.service
        systemctl restart rke2-agent.service

        # Wait for service to start
        log_info "⏳ 等待 RKE2 代理启动..."
        sleep 30

        # Check service status
        if systemctl is-active --quiet rke2-agent; then
            log_success "RKE2 代理服务已成功启动"
        else
            log_error "RKE2 代理服务启动失败"
            systemctl status rke2-agent
            journalctl -u rke2-agent --no-pager -l
            exit 1
        fi

        # Add RKE2 binaries to PATH
        echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> ~/.bashrc
        export PATH=$PATH:/var/lib/rancher/rke2/bin

        # Configure firewall
        log_info "🔥 配置防火墙..."
        configure_firewall() {
            # Open required ports for RKE2 agent
            if command -v ufw >/dev/null 2>&1; then
                ufw allow 10250/tcp  # kubelet API
                ufw allow 8472/udp   # Flannel VXLAN
                ufw allow 51820/udp  # Flannel Wireguard
                ufw allow 51821/udp  # Flannel Wireguard IPv6
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port=10250/tcp
                firewall-cmd --permanent --add-port=8472/udp
                firewall-cmd --permanent --add-port=51820/udp
                firewall-cmd --permanent --add-port=51821/udp
                firewall-cmd --reload
            elif command -v iptables >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
                iptables -A INPUT -p udp --dport 8472 -j ACCEPT
                iptables -A INPUT -p udp --dport 51820 -j ACCEPT
                iptables -A INPUT -p udp --dport 51821 -j ACCEPT
            fi
        }
        configure_firewall
        log_success "防火墙规则已配置"

        # Wait for agent to register with cluster
        log_info "⏳ 等待代理节点注册到集群..."
        for i in {1..30}; do
            if systemctl is-active --quiet rke2-agent; then
                log_success "代理节点已成功注册"
                break
            fi
            echo "  等待代理节点注册... ($i/30)"
            sleep 10
        done

        log_success "🎉 RKE2 代理节点 #{node[:name]} 安装完成！"

        log_info "📈 安装摘要:"
        echo "  - ✅ RKE2 代理已安装并启动"
        echo "  - ✅ 防火墙规则已设置"
        echo "  - ✅ 连接到负载均衡器: #{server_url}"
        echo "  - ✅ 使用集群 Token: #{token}"

        log_info "🌐 连接信息:"
        echo "  负载均衡器地址: #{loadbalancer_ip}"
        echo "  RKE2 注册服务: #{server_url}"
        echo "  节点角色: Agent (Worker)"

        log_info "💡 验证节点状态:"
        echo "  在 master 节点上运行以下命令验证节点是否加入:"
        echo "  kubectl get nodes"
        echo "  kubectl get nodes #{node[:name]} -o wide"

        exit 0
      SCRIPT
    end

    # Display cluster information after deployment
    #
    # @param agent_nodes [Array<Hash>] Array of agent node configurations
    def display_cluster_info(agent_nodes)
      loadbalancer_ip = @config['loadbalancer_ip']
      token = @config['token'] || 'rke2Secret123456'

      @logger.info("\n🌐 RKE2 Agent 节点部署完成！")

      puts "\n📋 集群信息:"
      puts "  代理节点数: #{agent_nodes.length}"
      puts "  集群 Token: #{token}"
      puts "  负载均衡地址: #{loadbalancer_ip}"
      puts "  Kubernetes API: https://#{loadbalancer_ip}:6443"
      puts "  RKE2 注册服务: https://#{loadbalancer_ip}:9345"

      puts "\n🖥️  代理节点列表:"
      agent_nodes.each do |node|
        puts "  - #{node[:name]}: #{node[:ip]} (通过 HAProxy 连接)"
      end

      puts "\n💡 下一步操作:"
      puts '  1. 验证节点状态:'
      puts '     kubectl get nodes'
      puts '     kubectl get nodes -o wide'
      puts ''
      puts '  2. 检查 Pod 状态:'
      puts '     kubectl get pods -A'
      puts '     kubectl get pods -n kube-system'
      puts ''
      puts '  3. 部署应用程序:'
      puts '     kubectl create deployment nginx --image=nginx'
      puts '     kubectl expose deployment nginx --port=80 --type=NodePort'
      puts ''
      puts '  4. 配置 Ingress 或其他网络组件 (如果需要)'
    end

    # Class methods for easy access
    class << self
      # Deploy RKE2 agent on all agent nodes
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if all agent nodes deployed successfully
      def deploy_all(config_file = 'config.yml', logger: nil)
        agent = new(config_file, logger: logger)
        agent.deploy_all_agents
      end

      # Deploy RKE2 agent on a specific node
      #
      # @param node_name [String] Name of the agent node to deploy
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if agent node deployed successfully
      def deploy_node(node_name, config_file = 'config.yml', logger: nil)
        agent = new(config_file, logger: logger)
        agent.load_configuration

        agent_nodes = agent.extract_agent_nodes
        target_node = agent_nodes.find { |node| node[:name] == node_name }

        unless target_node
          agent.logger.error("代理节点 '#{node_name}' 在配置文件中未找到")
          return false
        end

        agent.logger.deploy("🚀 开始部署代理节点 #{node_name}")
        result = agent.deploy_single_agent(target_node)

        if result
          agent.logger.success("🎉 代理节点 #{node_name} 部署完成！")
        else
          agent.logger.error("❌ 代理节点 #{node_name} 部署失败")
        end

        result
      end
    end
  end
end

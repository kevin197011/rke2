# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require_relative 'config'
require_relative 'helper'
require_relative 'logger'
require_relative 'bootstrap'
require_relative 'proxy'
require_relative 'server'
require_relative 'agent'
require_relative 'finalizer'

module RKE2
  # RKE2 Deployment orchestration class
  class Deploy
    include RKE2::Config

    attr_reader :logger, :helper, :config

    # Initialize deployment with configuration
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @helper = RKE2::Helper.new(logger: @logger)
      @config_file = config_file
      @config = nil
      @deployment_start_time = nil
    end

    # Run complete RKE2 cluster deployment
    #
    # @param skip_bootstrap [Boolean] Skip system initialization
    # @param skip_haproxy [Boolean] Skip HAProxy configuration
    # @param skip_agents [Boolean] Skip agent deployment
    # @param skip_finalization [Boolean] Skip finalization
    # @param auto_reboot [Boolean] Automatically reboot after bootstrap
    # @return [Boolean] True if deployment successful
    def run(skip_bootstrap: false, skip_haproxy: false, skip_agents: false, skip_finalization: false,
            auto_reboot: false)
      @deployment_start_time = Time.now
      @logger.deploy('🚀 开始 RKE2 集群完整部署')

      begin
        # Pre-deployment validation
        unless pre_deployment_validation
          @logger.fatal('部署前验证失败，停止部署')
          return false
        end

        # Calculate total steps
        total_steps = calculate_total_steps(skip_bootstrap, skip_haproxy, skip_agents, skip_finalization)
        current_step = 0

        # Step 1: System Bootstrap (if not skipped)
        unless skip_bootstrap
          current_step += 1
          @logger.step(current_step, total_steps, '系统初始化和性能优化')
          unless run_bootstrap(auto_reboot)
            @logger.fatal('系统初始化失败，停止部署')
            return false
          end
        end

        # Step 2: Configure HAProxy (if not skipped)
        unless skip_haproxy
          current_step += 1
          @logger.step(current_step, total_steps, '配置 HAProxy 负载均衡器')
          unless deploy_haproxy
            @logger.fatal('HAProxy 配置失败，停止部署')
            return false
          end
        end

        # Step 3: Deploy RKE2 Server nodes
        current_step += 1
        @logger.step(current_step, total_steps, '部署 RKE2 Server 节点')
        unless deploy_servers
          @logger.fatal('RKE2 Server 部署失败，停止部署')
          return false
        end

        # Step 4: Deploy RKE2 Agent nodes (if not skipped)
        unless skip_agents
          current_step += 1
          @logger.step(current_step, total_steps, '部署 RKE2 Agent 节点')
          unless deploy_agents
            @logger.fatal('RKE2 Agent 部署失败，停止部署')
            return false
          end
        end

        # Step 5: Finalize cluster configuration (if not skipped)
        unless skip_finalization
          current_step += 1
          @logger.step(current_step, total_steps, '完成集群最终配置')
          @logger.warn('集群最终配置失败，但核心部署已完成') unless finalize_cluster
        end

        # Step 6: Post-deployment verification
        current_step += 1
        @logger.step(current_step, total_steps, '验证集群状态')
        cluster_healthy = verify_deployment

        # Display deployment summary
        display_deployment_summary(cluster_healthy, skip_bootstrap, skip_haproxy, skip_agents, skip_finalization)

        cluster_healthy
      rescue StandardError => e
        @logger.fatal("部署过程中发生异常: #{e.message}")
        @logger.debug("异常堆栈: #{e.backtrace.join("\n")}")
        false
      end
    end

    # Run quick deployment (servers only, no bootstrap)
    #
    # @return [Boolean] True if deployment successful
    def run_quick
      @logger.deploy('⚡ 开始 RKE2 快速部署 (仅 Server 节点)')
      run(skip_bootstrap: true, skip_haproxy: true, skip_agents: true, skip_finalization: false)
    end

    # Run HA deployment (with HAProxy and bootstrap)
    #
    # @return [Boolean] True if deployment successful
    def run_ha
      @logger.deploy('🏢 开始 RKE2 高可用部署')
      run(skip_bootstrap: false, skip_haproxy: false, skip_agents: false, skip_finalization: false)
    end

    # Run server-only deployment
    #
    # @return [Boolean] True if deployment successful
    def run_servers_only
      @logger.deploy('🎛️  开始 RKE2 服务器部署 (不包含 Agent)')
      run(skip_bootstrap: false, skip_haproxy: false, skip_agents: true, skip_finalization: false)
    end

    # Run full deployment with bootstrap
    #
    # @return [Boolean] True if deployment successful
    def run_full_with_bootstrap
      @logger.deploy('🔧 开始 RKE2 完整部署 (包含系统初始化)')
      run(skip_bootstrap: false, skip_haproxy: false, skip_agents: false, skip_finalization: false)
    end

    # Run bootstrap only
    #
    # @param auto_reboot [Boolean] Automatically reboot after bootstrap
    # @return [Boolean] True if bootstrap successful
    def run_bootstrap_only(auto_reboot: true)
      @logger.deploy('🚀 开始系统初始化和性能优化')

      begin
        load_configuration
        validate_configuration
        run_bootstrap(auto_reboot)
      rescue StandardError => e
        @logger.fatal("系统初始化异常: #{e.message}")
        false
      end
    end

    private

    # Calculate total steps based on what's being skipped
    #
    # @param skip_bootstrap [Boolean] Skip system initialization
    # @param skip_haproxy [Boolean] Skip HAProxy configuration
    # @param skip_agents [Boolean] Skip agent deployment
    # @param skip_finalization [Boolean] Skip finalization
    # @return [Integer] Total number of steps
    def calculate_total_steps(skip_bootstrap, skip_haproxy, skip_agents, skip_finalization)
      steps = 2 # Always have server deployment and verification
      steps += 1 unless skip_bootstrap
      steps += 1 unless skip_haproxy
      steps += 1 unless skip_agents
      steps += 1 unless skip_finalization
      steps
    end

    # Pre-deployment validation
    #
    # @return [Boolean] True if validation passes
    def pre_deployment_validation
      @logger.info('🔍 执行部署前验证...')

      # Load and validate configuration
      begin
        load_configuration
        validate_configuration
      rescue StandardError => e
        @logger.error("配置验证失败: #{e.message}")
        return false
      end

      # Validate node connectivity
      unless validate_node_connectivity
        @logger.error('节点连接验证失败')
        return false
      end

      # Check for existing installations
      check_existing_installations

      @logger.success('部署前验证完成')
      true
    end

    # Load configuration from file
    def load_configuration
      @logger.debug("加载配置文件: #{@config_file}")
      raise ArgumentError, "配置文件 #{@config_file} 不存在" unless File.exist?(@config_file)

      @config = RKE2::Config.load_config(@config_file)
      @logger.info('配置文件加载完成')
    end

    # Validate configuration
    def validate_configuration
      @logger.debug('验证配置文件')

      # Basic validation
      raise ArgumentError, '配置文件中缺少 nodes 配置或格式错误' unless @config['nodes']&.is_a?(Array)
      raise ArgumentError, '配置文件中没有定义任何节点' if @config['nodes'].empty?

      # Extract node information
      server_nodes = @config['nodes'].select { |node| node['role'] == 'server' }
      agent_nodes = @config['nodes'].select { |node| node['role'] == 'agent' }
      lb_nodes = @config['nodes'].select { |node| node['role'] == 'lb' }

      # Validate node roles
      raise ArgumentError, '配置文件中必须至少有一个 server 节点' if server_nodes.empty?

      @logger.info("配置验证完成 - Server: #{server_nodes.length}, Agent: #{agent_nodes.length}, LB: #{lb_nodes.length}")

      # Validate token
      @logger.warn('配置文件中未设置 token，将使用默认 token') if @config['token'].nil? || @config['token'].to_s.strip.empty?

      # Validate load balancer configuration
      if lb_nodes.any? && (@config['loadbalancer_ip'].nil? || @config['loadbalancer_ip'].to_s.strip.empty?)
        @logger.warn('配置了负载均衡节点但未设置 loadbalancer_ip')
      end

      true
    end

    # Validate node connectivity
    #
    # @return [Boolean] True if all nodes are reachable
    def validate_node_connectivity
      @logger.info('🔗 验证节点连接...')

      all_nodes = @config['nodes']
      username = @config['username'] || 'root'
      ssh_key = @config['ssh_key'] || '~/.ssh/id_rsa'

      success_count = 0
      failed_nodes = []

      all_nodes.each do |node|
        name = node['name']
        ip = node['ip']
        node_username = node['username'] || username
        node_ssh_key = node['ssh_key'] || ssh_key

        @logger.debug("测试节点 #{name} (#{ip}) 连接...")

        if @helper.host_reachable?(ip, 22, 10)
          if @helper.test_ssh_connection(ip, node_username, node_ssh_key)
            success_count += 1
            @logger.success("节点 #{name} 连接正常")
          else
            failed_nodes << "#{name} (SSH失败)"
            @logger.error("节点 #{name} SSH 连接失败")
          end
        else
          failed_nodes << "#{name} (不可达)"
          @logger.error("节点 #{name} 不可达")
        end
      end

      if failed_nodes.any?
        @logger.error("#{failed_nodes.length} 个节点连接失败: #{failed_nodes.join(', ')}")
        return false
      end

      @logger.success("所有 #{success_count} 个节点连接验证通过")
      true
    end

    # Check for existing RKE2 installations
    def check_existing_installations
      @logger.info('🔍 检查现有 RKE2 安装...')

      all_nodes = @config['nodes']
      username = @config['username'] || 'root'
      ssh_key = @config['ssh_key'] || '~/.ssh/id_rsa'

      existing_installations = []

      all_nodes.each do |node|
        name = node['name']
        ip = node['ip']
        node_username = node['username'] || username
        node_ssh_key = node['ssh_key'] || ssh_key

        # Check for RKE2 installation
        check_result = @helper.ssh_exec(
          ip,
          node_username,
          'systemctl list-unit-files | grep -E "(rke2-server|rke2-agent)" || echo "not_found"',
          node_ssh_key,
          skip_sudo: false
        )

        if check_result[:success] && !check_result[:output].include?('not_found')
          existing_installations << name
          @logger.warn("节点 #{name} 已安装 RKE2")
        end
      end

      if existing_installations.any?
        @logger.warn("发现 #{existing_installations.length} 个节点已有 RKE2 安装: #{existing_installations.join(', ')}")
        @logger.warn('部署可能会覆盖现有配置')
      else
        @logger.info('未发现现有 RKE2 安装')
      end
    end

    # Run system bootstrap
    #
    # @param auto_reboot [Boolean] Automatically reboot after bootstrap
    # @return [Boolean] True if bootstrap successful
    def run_bootstrap(auto_reboot = true)
      @logger.loading('执行系统初始化和性能优化...')

      begin
        bootstrap = RKE2::Bootstrap.new(@config_file, logger: @logger)
        result = bootstrap.run(reboot: auto_reboot)

        if result
          @logger.success('系统初始化和性能优化完成')

          if auto_reboot
            @logger.info('所有节点已重启，等待服务稳定...')
            sleep 30
          else
            @logger.info('💡 建议手动重启所有节点以确保优化配置生效')
          end

          true
        else
          @logger.error('系统初始化和性能优化失败')
          false
        end
      rescue StandardError => e
        @logger.error("系统初始化异常: #{e.message}")
        false
      end
    end

    # Deploy HAProxy load balancer
    #
    # @return [Boolean] True if deployment successful
    def deploy_haproxy
      @logger.loading('部署 HAProxy 负载均衡器...')

      begin
        proxy = RKE2::Proxy.new(@config_file, logger: @logger)
        result = proxy.configure_all_lb_nodes

        if result
          @logger.success('HAProxy 负载均衡器部署完成')

          # Wait for HAProxy to be ready
          @logger.info('等待 HAProxy 服务启动...')
          sleep 10

          true
        else
          @logger.error('HAProxy 负载均衡器部署失败')
          false
        end
      rescue StandardError => e
        @logger.error("HAProxy 部署异常: #{e.message}")
        false
      end
    end

    # Deploy RKE2 server nodes
    #
    # @return [Boolean] True if deployment successful
    def deploy_servers
      @logger.loading('部署 RKE2 Server 节点...')

      begin
        server = RKE2::Server.new(@config_file, logger: @logger)
        result = server.deploy_all_servers

        if result
          @logger.success('RKE2 Server 节点部署完成')

          # Wait for servers to be fully ready
          @logger.info('等待 RKE2 Server 服务完全启动...')
          sleep 30

          true
        else
          @logger.error('RKE2 Server 节点部署失败')
          false
        end
      rescue StandardError => e
        @logger.error("RKE2 Server 部署异常: #{e.message}")
        false
      end
    end

    # Deploy RKE2 agent nodes
    #
    # @return [Boolean] True if deployment successful
    def deploy_agents
      @logger.loading('部署 RKE2 Agent 节点...')

      # Check if there are any agent nodes
      agent_nodes = @config['nodes'].select { |node| node['role'] == 'agent' }
      if agent_nodes.empty?
        @logger.info('配置文件中没有 Agent 节点，跳过 Agent 部署')
        return true
      end

      begin
        agent = RKE2::Agent.new(@config_file, logger: @logger)
        result = agent.deploy_all_agents

        if result
          @logger.success('RKE2 Agent 节点部署完成')
          true
        else
          @logger.error('RKE2 Agent 节点部署失败')
          false
        end
      rescue StandardError => e
        @logger.error("RKE2 Agent 部署异常: #{e.message}")
        false
      end
    end

    # Finalize cluster configuration
    #
    # @return [Boolean] True if finalization successful
    def finalize_cluster
      @logger.loading('执行集群最终配置...')

      begin
        finalizer = RKE2::Finalizer.new(@config_file, logger: @logger)
        result = finalizer.finalize_cluster

        if result
          @logger.success('集群最终配置完成')
          true
        else
          @logger.error('集群最终配置失败')
          false
        end
      rescue StandardError => e
        @logger.error("集群最终配置异常: #{e.message}")
        false
      end
    end

    # Verify deployment
    #
    # @return [Boolean] True if verification successful
    def verify_deployment
      @logger.loading('验证集群部署状态...')

      begin
        finalizer = RKE2::Finalizer.new(@config_file, logger: @logger)
        result = finalizer.verify_cluster_status

        if result
          @logger.success('集群状态验证通过')
          true
        else
          @logger.warn('集群状态验证失败，但部署可能仍然成功')
          false
        end
      rescue StandardError => e
        @logger.error("集群验证异常: #{e.message}")
        false
      end
    end

    # Display deployment summary
    #
    # @param cluster_healthy [Boolean] Whether cluster is healthy
    # @param skip_bootstrap [Boolean] Whether bootstrap was skipped
    # @param skip_haproxy [Boolean] Whether HAProxy was skipped
    # @param skip_agents [Boolean] Whether agents were skipped
    # @param skip_finalization [Boolean] Whether finalization was skipped
    def display_deployment_summary(cluster_healthy, skip_bootstrap, skip_haproxy, skip_agents, skip_finalization)
      deployment_time = Time.now - @deployment_start_time

      @logger.info("\n" + '=' * 80)
      @logger.info('🎉 RKE2 集群部署完成！')
      @logger.info('=' * 80)

      puts "\n📊 部署摘要:"
      puts "  部署时间: #{format_duration(deployment_time)}"
      puts "  集群状态: #{cluster_healthy ? '✅ 健康' : '⚠️  需要检查'}"

      # Node summary
      server_nodes = @config['nodes'].select { |node| node['role'] == 'server' }
      agent_nodes = @config['nodes'].select { |node| node['role'] == 'agent' }
      lb_nodes = @config['nodes'].select { |node| node['role'] == 'lb' }

      puts "\n🖥️  节点部署状态:"
      puts "  Server 节点: #{server_nodes.length} 个 ✅"
      puts "  Agent 节点: #{skip_agents ? '跳过' : "#{agent_nodes.length} 个 ✅"}"
      puts "  负载均衡器: #{skip_haproxy ? '跳过' : "#{lb_nodes.length} 个 ✅"}"

      puts "\n🔧 组件部署状态:"
      puts "  系统初始化: #{skip_bootstrap ? '跳过' : '✅ 已完成'}"
      puts "  HAProxy 负载均衡: #{skip_haproxy ? '跳过' : '✅ 已部署'}"
      puts '  RKE2 Server: ✅ 已部署'
      puts "  RKE2 Agent: #{skip_agents ? '跳过' : '✅ 已部署'}"
      puts "  kubectl + Helm + K9s: #{skip_finalization ? '跳过' : '✅ 已配置'}"

      # Access information
      loadbalancer_ip = @config['loadbalancer_ip']
      first_server = server_nodes.first

      puts "\n🌐 集群访问信息:"
      if loadbalancer_ip && !skip_haproxy
        puts "  Kubernetes API: https://#{loadbalancer_ip}:6443"
        puts "  RKE2 注册服务: https://#{loadbalancer_ip}:9345"
        puts "  HAProxy 统计: http://#{loadbalancer_ip}:8404/stats"
      else
        puts "  Kubernetes API: https://#{first_server['ip']}:6443"
        puts "  RKE2 注册服务: https://#{first_server['ip']}:9345"
      end

      puts "\n🔑 认证信息:"
      puts "  集群 Token: #{@config['token'] || 'rke2Secret123456'}"
      puts '  kubeconfig: /etc/rancher/rke2/rke2.yaml (服务器节点)'

      puts "\n💡 下一步操作:"
      puts '  1. SSH 登录到任意 server 节点'
      puts '  2. 运行管理脚本:'
      puts '     ./cluster-info.sh    # 集群概览'
      puts '     ./helm-info.sh       # Helm 信息'
      puts '     k9s                  # 启动集群管理界面'
      puts '  3. 部署应用程序:'
      puts '     kubectl create deployment nginx --image=nginx'
      puts '     helm install my-app bitnami/nginx'

      unless cluster_healthy
        puts "\n⚠️  注意事项:"
        puts '  集群状态验证失败，建议手动检查:'
        puts '  - 检查所有节点的 RKE2 服务状态'
        puts '  - 验证网络连接和防火墙设置'
        puts '  - 查看服务日志: journalctl -u rke2-server'
      end

      unless skip_bootstrap
        puts "\n🚀 系统优化摘要:"
        puts '  - ✅ 时间同步已配置 (Asia/Hong_Kong)'
        puts '  - ✅ Swap 已禁用'
        puts '  - ✅ 内核模块已加载'
        puts '  - ✅ 系统参数已优化'
        puts '  - ✅ 系统限制已调整'
        puts '  - ✅ 防火墙已配置'
        puts '  - ✅ 性能优化已应用'
      end

      puts "\n" + '=' * 80
    end

    # Format duration in human readable format
    #
    # @param seconds [Float] Duration in seconds
    # @return [String] Formatted duration
    def format_duration(seconds)
      hours = (seconds / 3600).to_i
      minutes = ((seconds % 3600) / 60).to_i
      secs = (seconds % 60).to_i

      if hours > 0
        "#{hours}h #{minutes}m #{secs}s"
      elsif minutes > 0
        "#{minutes}m #{secs}s"
      else
        "#{secs}s"
      end
    end

    # Class methods for easy access
    class << self
      # Run complete deployment
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @param skip_bootstrap [Boolean] Skip system initialization
      # @param skip_haproxy [Boolean] Skip HAProxy configuration
      # @param skip_agents [Boolean] Skip agent deployment
      # @param skip_finalization [Boolean] Skip finalization
      # @param auto_reboot [Boolean] Automatically reboot after bootstrap
      # @return [Boolean] True if deployment successful
      def run(config_file = 'config.yml', logger: nil, skip_bootstrap: false, skip_haproxy: false, skip_agents: false,
              skip_finalization: false, auto_reboot: true)
        deploy = new(config_file, logger: logger)
        deploy.run(skip_bootstrap: skip_bootstrap, skip_haproxy: skip_haproxy, skip_agents: skip_agents,
                   skip_finalization: skip_finalization, auto_reboot: auto_reboot)
      end

      # Run quick deployment
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if deployment successful
      def run_quick(config_file = 'config.yml', logger: nil)
        deploy = new(config_file, logger: logger)
        deploy.run_quick
      end

      # Run HA deployment
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if deployment successful
      def run_ha(config_file = 'config.yml', logger: nil)
        deploy = new(config_file, logger: logger)
        deploy.run_ha
      end

      # Run servers only deployment
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if deployment successful
      def run_servers_only(config_file = 'config.yml', logger: nil)
        deploy = new(config_file, logger: logger)
        deploy.run_servers_only
      end

      # Run full deployment with bootstrap
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if deployment successful
      def run_full_with_bootstrap(config_file = 'config.yml', logger: nil)
        deploy = new(config_file, logger: logger)
        deploy.run_full_with_bootstrap
      end

      # Run bootstrap only
      #
      # @param config_file [String] Path to configuration file
      # @param auto_reboot [Boolean] Automatically reboot after bootstrap
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if bootstrap successful
      def run_bootstrap_only(config_file = 'config.yml', auto_reboot: true, logger: nil)
        deploy = new(config_file, logger: logger)
        deploy.run_bootstrap_only(auto_reboot: auto_reboot)
      end
    end
  end
end

# frozen_string_literal: true

# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

require_relative 'config'
require_relative 'helper'
require_relative 'logger'

# Finalizer class for cluster configuration
module RKE2
  # Finalizer handles post-deployment cluster configuration with enhanced error handling
  #
  # Leverages RKE2::Config, RKE2::Helper, and RKE2::Logger modules for:
  # - kubectl configuration with detailed error reporting
  # - Cluster status verification with nil-safe operations
  # - SSH operations with improved error handling
  class Finalizer
    attr_reader :logger

    # Initialize finalizer
    #
    # @param config_file [String] Path to configuration file
    # @param logger [RKE2::Logger] Logger instance
    def initialize(config_file = 'config.yml', logger: nil)
      @logger = logger || RKE2::Logger.new
      @config_file = config_file
      @config = {}
      @helper = RKE2::Helper.new(logger: @logger)

      # Pre-load configuration for immediate availability
      begin
        load_configuration
        @logger.debug("配置文件已预加载: #{@config_file}")
      rescue StandardError => e
        @logger.debug("配置文件预加载失败: #{e.message}")
        # Don't fail initialization, let methods handle configuration loading as needed
      end
    end

    # Finalize cluster configuration
    #
    # @return [Boolean] True if finalization successful
    def finalize_cluster
      @logger.deploy('🏁 开始集群最终配置')

      # Ensure configuration is loaded and valid
      return false unless ensure_configuration_loaded
      return false unless validate_configuration

      server_nodes = extract_server_nodes

      if server_nodes.empty?
        @logger.error('配置文件中未找到 server 节点')
        return false
      end

      @logger.info('测试节点连接性...')
      server_nodes.each do |node|
        unless test_node_connectivity(node)
          @logger.error("无法连接到服务器节点 #{node[:name]} (#{node[:ip]})")
          return false
        end
      end

      @logger.deploy('🔧 配置服务器节点 kubectl 访问')
      success_count = 0
      failed_nodes = []

      server_nodes.each do |node|
        if configure_single_server_kubectl(node)
          success_count += 1
        else
          failed_nodes << node[:name]
        end
      end

      if failed_nodes.empty?
        @logger.success("🎉 所有 #{success_count} 个服务器节点 kubectl 配置成功")
        display_finalization_info(server_nodes)
        verify_cluster_status
        true
      else
        @logger.error("❌ #{failed_nodes.length} 个服务器节点配置失败: #{failed_nodes.join(', ')}")
        @logger.info("ℹ️ ✅ #{success_count} 个服务器节点配置成功")
        @logger.error('集群最终配置失败')
        @logger.warn('⚠️ 集群最终配置失败，但核心部署已完成')
        false
      end
    end

    # Configure kubectl access for a single server node
    #
    # @param node [Hash] Server node configuration
    # @return [Boolean] True if configuration successful
    def configure_single_server_kubectl(node)
      @logger.time("服务器节点 #{node[:name]} kubectl 配置") do
        success = configure_kubectl_access(node)
        if success
          @logger.success("服务器节点 #{node[:name]} kubectl 配置完成")
        else
          @logger.error("服务器节点 #{node[:name]} kubectl 配置失败")
        end
        success
      end
    end

    # Verify cluster status
    #
    # @return [Boolean] True if cluster is healthy
    def verify_cluster_status
      @logger.deploy('🔍 验证集群状态')

      # Ensure configuration is loaded
      unless ensure_configuration_loaded
        @logger.error('❌ 配置信息无效，无法验证集群状态')
        return false
      end

      unless @config['nodes']
        @logger.error('❌ 配置中缺少节点信息，无法验证集群状态')
        return false
      end

      server_nodes = extract_server_nodes
      if server_nodes.empty?
        @logger.error('❌ 未找到可用的 server 节点进行集群验证')
        return false
      end

      # Use first server node for verification
      first_server = server_nodes.first
      @logger.debug("使用服务器节点 #{first_server[:name]} 进行集群验证")

      begin
        cluster_info = get_cluster_info(first_server)

        if cluster_info[:success]
          @logger.success('🎉 集群状态验证成功')
          display_cluster_status(cluster_info, server_nodes)
          true
        else
          @logger.error('❌ 集群状态验证失败')
          false
        end
      rescue StandardError => e
        @logger.error("❌ 集群验证异常: #{e.message}")
        @logger.debug("集群验证错误详情: #{e.backtrace.join("\n")}")
        false
      end
    end

    private

    # Ensure configuration is loaded and valid
    #
    # @return [Boolean] True if configuration is available
    def ensure_configuration_loaded
      return true if @config && @config.is_a?(Hash) && !@config.empty?

      @logger.debug('配置未加载或无效，尝试重新加载')
      load_configuration && validate_configuration
    end

    # Load configuration from file using Config module
    #
    # @return [Boolean] True if configuration loaded successfully
    def load_configuration
      @logger.debug("加载配置文件: #{@config_file}")

      unless File.exist?(@config_file)
        @logger.error("配置文件不存在: #{@config_file}")
        return false
      end

      @config = RKE2::Config.load_config(@config_file)
      true
    rescue StandardError => e
      @logger.error("配置文件加载失败: #{e.message}")
      false
    end

    # Validate configuration with detailed checks
    #
    # @return [Boolean] True if configuration is valid
    def validate_configuration
      @logger.debug('验证配置文件')

      unless @config.is_a?(Hash) && !@config.empty?
        @logger.error('配置文件为空或格式无效')
        return false
      end

      return false unless validate_nodes_config

      return false unless validate_server_nodes_exist

      validate_connection_config
    end

    # Validate nodes configuration section
    #
    # @return [Boolean] True if nodes configuration is valid
    def validate_nodes_config
      unless @config && @config['nodes'].is_a?(Array) && @config['nodes'].any?
        @logger.error('配置文件中未找到有效的节点配置')
        return false
      end

      true
    end

    # Validate that at least one server node exists
    #
    # @return [Boolean] True if server nodes exist
    def validate_server_nodes_exist
      return false unless @config && @config['nodes'].is_a?(Array)

      server_nodes = @config['nodes'].select { |node| node['role'] == 'server' }

      if server_nodes.empty?
        @logger.error('配置文件中未找到 server 节点')
        return false
      end

      @logger.debug("找到 #{server_nodes.length} 个 server 节点")
      true
    end

    # Validate connection configuration
    #
    # @return [Boolean] True if connection configuration is valid
    def validate_connection_config
      username = get_ssh_username
      ssh_key = get_ssh_key_path

      @logger.debug('连接配置验证', {
                      username: username,
                      ssh_key: ssh_key,
                      loadbalancer_ip: get_loadbalancer_ip
                    })

      # Check if SSH key file exists
      expanded_key_path = File.expand_path(ssh_key)
      unless File.exist?(expanded_key_path)
        @logger.warn("SSH 密钥文件不存在: #{expanded_key_path}")
        @logger.warn('将尝试使用 SSH agent 或密码认证')
      end

      true
    end

    # Extract server nodes from configuration with default values
    #
    # @return [Array<Hash>] Array of server node configurations
    def extract_server_nodes
      return [] unless @config && @config['nodes'].is_a?(Array)

      @config['nodes'].select { |node| node['role'] == 'server' }.map do |node|
        extract_node_config(node)
      end
    end

    # Extract and normalize node configuration
    #
    # @param node [Hash] Raw node configuration from config file
    # @return [Hash] Normalized node configuration
    def extract_node_config(node)
      {
        name: node['name'],
        ip: node['ip'],
        username: get_ssh_username,
        ssh_key: get_ssh_key_path
      }
    end

    # Test connectivity to a node using Helper
    #
    # @param node [Hash] Node configuration
    # @return [Boolean] True if connection successful
    def test_node_connectivity(node)
      @logger.debug('测试节点连接', { node: node[:name], ip: node[:ip] })

      @helper.test_ssh_connection(
        node[:ip],
        node[:username],
        node[:ssh_key],
        timeout: 30
      )
    rescue StandardError => e
      @logger.debug("节点连接测试失败: #{e.message}")
      false
    end

    # Configure kubectl access for a server node
    #
    # @param node [Hash] Server node configuration
    # @return [Boolean] True if configuration successful
    def configure_kubectl_access(node)
      @logger.loading("配置服务器节点 #{node[:name]} kubectl 访问")

      # Generate and execute kubectl configuration script
      script_content = generate_kubectl_config_script(node)
      script_path = "/tmp/rke2_kubectl_config_#{node[:name]}_#{Time.now.to_i}.sh"

      success = execute_remote_script(node, script_content, script_path, 'kubectl 配置')

      if success && verify_kubectl_access(node)
        @logger.success("服务器节点 #{node[:name]} kubectl 访问配置成功")
        true
      else
        @logger.error("服务器节点 #{node[:name]} kubectl 访问配置失败")
        false
      end
    end

    # Execute a script on remote node with upload, execution, and cleanup
    #
    # @param node [Hash] Node configuration
    # @param script_content [String] Script content to execute
    # @param script_path [String] Remote path for script
    # @param operation_name [String] Name of operation for logging
    # @return [Boolean] True if execution successful
    def execute_remote_script(node, script_content, script_path, operation_name)
      # Upload script using Helper's ssh_upload_content
      @logger.loading("上传 #{operation_name} 脚本到 #{node[:name]}")
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

      # Execute configuration script
      @logger.loading("执行 #{operation_name} 脚本")
      exec_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        "chmod +x #{script_path} && #{script_path}",
        node[:ssh_key],
        timeout: 120, # 2 minutes timeout
        skip_sudo: false # Use sudo for script execution
      )

      # Cleanup script
      @helper.ssh_exec(node[:ip], node[:username], "rm -f #{script_path}", node[:ssh_key], skip_sudo: false)

      if exec_result[:success]
        @logger.info("#{operation_name} 脚本执行完成", {
                       node: node[:name],
                       output_length: exec_result[:output].length
                     })

        # Log script output in debug mode
        @logger.debug("#{operation_name} 脚本输出:\n#{exec_result[:output]}")
        true
      else
        @logger.error("#{operation_name} 脚本执行失败", {
                        node: node[:name],
                        error: exec_result[:error],
                        exit_code: exec_result[:exit_code],
                        output: exec_result[:output]
                      })
        @logger.debug("#{operation_name} 失败脚本输出:\n#{exec_result[:output]}")
        false
      end
    end

    # Verify kubectl access on a server node
    #
    # @param node [Hash] Server node configuration
    # @return [Boolean] True if kubectl access works
    def verify_kubectl_access(node)
      @logger.debug("验证服务器节点 #{node[:name]} kubectl 访问")

      # Test kubectl get nodes with proper PATH and Ready check
      result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        'export PATH=$PATH:/var/lib/rancher/rke2/bin && kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes --no-headers 2>/dev/null | grep -c Ready',
        node[:ssh_key],
        skip_sudo: false
      )

      if result[:success]
        ready_count = result[:output].strip.to_i
        if ready_count > 0
          @logger.success("服务器节点 #{node[:name]} kubectl 访问正常 (#{ready_count} 个 Ready 节点)")
          true
        else
          @logger.debug("kubectl 验证结果: #{result[:output]}")
          @logger.warn("服务器节点 #{node[:name]} kubectl 配置成功，但集群节点未就绪")
          true # Configuration is successful, cluster might still be starting
        end
      else
        @logger.debug("kubectl 验证失败: #{result[:error] || result[:output]}")
        @logger.error("服务器节点 #{node[:name]} kubectl 访问失败")
        false
      end
    end

    # Get cluster information from a server node
    #
    # @param node [Hash] Server node configuration
    # @return [Hash] Cluster information
    def get_cluster_info(node)
      @logger.debug("获取集群信息从服务器节点 #{node[:name]}")

      result = {
        success: false,
        nodes: [],
        pods: [],
        version: nil,
        cluster_ip: nil
      }

      # Get cluster version
      version_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        'kubectl version --client=true -o yaml 2>/dev/null | grep gitVersion | cut -d: -f2 | tr -d \' \"\' || echo "Unknown"',
        node[:ssh_key],
        skip_sudo: false
      )

      result[:version] = version_result[:output].strip if version_result[:success]

      # Get nodes
      nodes_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        'kubectl get nodes -o wide --no-headers 2>/dev/null',
        node[:ssh_key],
        skip_sudo: false
      )

      result[:nodes] = nodes_result[:output].strip.split("\n").map(&:strip).reject(&:empty?) if nodes_result[:success]

      # Get system pods
      pods_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        'kubectl get pods -n kube-system --no-headers 2>/dev/null | grep -E "(Running|Ready)" | wc -l',
        node[:ssh_key],
        skip_sudo: false
      )

      result[:pods] = pods_result[:output].strip.to_i if pods_result[:success]

      # Get cluster service IP
      cluster_ip_result = @helper.ssh_exec(
        node[:ip],
        node[:username],
        'kubectl get svc kubernetes -o jsonpath="{.spec.clusterIP}" 2>/dev/null',
        node[:ssh_key],
        skip_sudo: false
      )

      result[:cluster_ip] = cluster_ip_result[:output].strip if cluster_ip_result[:success]

      result[:success] = !result[:nodes].empty?
      result
    end

    # Generate kubectl configuration script
    #
    # @param node [Hash] Server node configuration
    # @return [String] Configuration script content
    def generate_kubectl_config_script(node)
      loadbalancer_ip = get_loadbalancer_ip

      <<~SCRIPT
                #!/bin/bash
        # kubectl Configuration Script for #{node[:name]}
        # Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}
        set -euo pipefail

        echo "🔧 配置服务器节点 #{node[:name]} kubectl 访问..."

        # Function for error handling
        handle_error() {
            echo "❌ 错误: $1"
            echo "📋 当前用户: $(whoami)"
            echo "📂 当前目录: $(pwd)"
            echo "🔍 RKE2 文件检查:"
            [ -f /etc/rancher/rke2/rke2.yaml ] && echo "  ✅ /etc/rancher/rke2/rke2.yaml 存在" || echo "  ❌ /etc/rancher/rke2/rke2.yaml 不存在"
            [ -f /var/lib/rancher/rke2/bin/kubectl ] && echo "  ✅ kubectl 二进制存在" || echo "  ❌ kubectl 二进制不存在"
            exit 1
        }

        # Check if RKE2 kubeconfig exists
        if [ ! -f /etc/rancher/rke2/rke2.yaml ]; then
            handle_error "RKE2 kubeconfig 文件不存在: /etc/rancher/rke2/rke2.yaml"
        fi

        # Check if kubectl binary exists
        if [ ! -f /var/lib/rancher/rke2/bin/kubectl ]; then
            handle_error "kubectl 二进制文件不存在: /var/lib/rancher/rke2/bin/kubectl"
        fi

        # Create .kube directory and copy config
        echo "📁 配置 kubectl 访问..."
        mkdir -p /root/.kube || handle_error "无法创建 /root/.kube 目录"
        cp /etc/rancher/rke2/rke2.yaml /root/.kube/config || handle_error "无法复制 kubeconfig 文件"
        chmod 600 /root/.kube/config || handle_error "无法设置 kubeconfig 权限"
        chown root:root /root/.kube/config || handle_error "无法设置 kubeconfig 所有者"

                #{if loadbalancer_ip
                    "# Update server URL to load balancer\n" +
                    "echo \"🌐 更新 kubeconfig 为负载均衡器地址: #{loadbalancer_ip}\"\n" +
                    "sed -i 's/127.0.0.1/#{loadbalancer_ip}/g' /root/.kube/config || handle_error \"无法更新 kubeconfig 服务器地址\""
                  else
                    'echo "🏠 使用本地服务器地址 (未配置负载均衡器)"'
                  end}

        # Add kubectl symlink
                if [ ! -f /usr/local/bin/kubectl ]; then
            echo "🔗 创建 kubectl 符号链接"
            ln -sf /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl || echo "⚠️  无法创建 kubectl 符号链接，继续..."
        fi

        # Add PATH to bashrc if not exists
        if ! grep -q "/var/lib/rancher/rke2/bin" /root/.bashrc 2>/dev/null; then
            echo "📝 添加 RKE2 binaries 到 PATH"
            echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> /root/.bashrc || echo "⚠️  无法更新 bashrc，继续..."
        fi

                # Test kubectl access
        echo "🧪 测试 kubectl 访问..."
                export PATH=$PATH:/var/lib/rancher/rke2/bin
        if kubectl --kubeconfig /root/.kube/config get nodes >/dev/null 2>&1; then
            echo "✅ kubectl 配置完成，集群访问正常"
        else
            echo "⚠️  kubectl 配置完成，但集群可能仍在启动中"
            echo "🔍 kubectl 详细输出:"
            kubectl --kubeconfig /root/.kube/config get nodes 2>&1 || echo "kubectl 命令执行失败"
        fi

        echo "🎉 #{node[:name]} kubectl 配置脚本执行完成"
                exit 0
      SCRIPT
    end

    # Display finalization information using logger
    #
    # @param server_nodes [Array<Hash>] Array of server node configurations
    def display_finalization_info(server_nodes)
      loadbalancer_ip = get_loadbalancer_ip

      @logger.success('🏁 集群最终配置完成！')

      @logger.info('📋 工具访问信息:')
      @logger.info('  所有服务器节点的 root 用户现在都可以使用:')
      @logger.info('  - kubectl: Kubernetes 命令行工具')
      @logger.info('  配置文件位置: /root/.kube/config')

      @logger.info('🖥️  已配置的服务器节点:')
      server_nodes.each do |node|
        @logger.info("  - #{node[:name]} (#{node[:ip]}): kubectl 已配置")
      end

      @logger.info('💡 下一步操作:')
      @logger.info('  1. SSH 登录到任意服务器节点')
      @logger.info('  2. 使用 kubectl 命令管理集群:')
      @logger.info('     kubectl get nodes')
      @logger.info('     kubectl get pods -A')

      return unless loadbalancer_ip

      @logger.network('🌐 集群访问地址:')
      @logger.network("  负载均衡器: #{loadbalancer_ip}")
      @logger.network("  Kubernetes API: https://#{loadbalancer_ip}:6443")
      @logger.network("  HAProxy 统计: http://#{loadbalancer_ip}:8404/stats")
    end

    # Display cluster status information using logger
    #
    # @param cluster_info [Hash] Cluster information
    # @param server_nodes [Array<Hash>] Server nodes
    def display_cluster_status(cluster_info, server_nodes)
      @logger.log_with_icon(:info, '📊 集群状态验证结果', :monitor)

      @logger.info('🔍 集群基本信息:')
      @logger.info("  Kubernetes 版本: #{cluster_info[:version] || '未知'}")
      @logger.info("  集群服务 IP: #{cluster_info[:cluster_ip] || '未知'}")
      @logger.info("  节点总数: #{cluster_info[:nodes].length}")
      @logger.info("  系统 Pod 数: #{cluster_info[:pods]}")

      @logger.info('🖥️  节点详情:')
      if cluster_info[:nodes].any?
        cluster_info[:nodes].each do |node_info|
          @logger.info("  #{node_info}")
        end
      else
        @logger.error('  ❌ 无法获取节点信息')
      end

      @logger.info('🎛️  服务器节点配置状态:')
      server_nodes.each do |node|
        @logger.success("  - #{node[:name]} (#{node[:ip]}): kubectl 已配置")
      end

      status_message = cluster_info[:success] ? '正常' : '异常'
      if cluster_info[:success]
        @logger.success("✅ 集群健康状态: #{status_message}")
      else
        @logger.error("❌ 集群健康状态: #{status_message}")
      end
    end

    # Class methods for easy access
    class << self
      # Finalize cluster configuration for all server nodes
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if finalization successful
      def finalize_all(config_file = 'config.yml', logger: nil)
        finalizer = new(config_file, logger: logger)
        finalizer.finalize_cluster
      end

      # Configure kubectl access for a specific server node
      #
      # @param node_name [String] Name of the server node
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if configuration successful
      def configure_node(node_name, config_file = 'config.yml', logger: nil)
        finalizer = new(config_file, logger: logger)
        finalizer.load_configuration

        server_nodes = finalizer.extract_server_nodes
        target_node = server_nodes.find { |node| node[:name] == node_name }

        unless target_node
          finalizer.logger.error("服务器节点 '#{node_name}' 在配置文件中未找到")
          return false
        end

        finalizer.logger.deploy("🔧 配置服务器节点 #{node_name} kubectl 访问")
        result = finalizer.configure_single_server_kubectl(target_node)

        if result
          finalizer.logger.success("🎉 服务器节点 #{node_name} kubectl 配置完成！")
        else
          finalizer.logger.error("❌ 服务器节点 #{node_name} kubectl 配置失败")
        end

        result
      end

      # Verify cluster status
      #
      # @param config_file [String] Path to configuration file
      # @param logger [RKE2::Logger] Logger instance
      # @return [Boolean] True if cluster is healthy
      def verify_cluster(config_file = 'config.yml', logger: nil)
        finalizer = new(config_file, logger: logger)
        finalizer.verify_cluster_status
      end
    end
    # Get loadbalancer IP from configuration
    #
    # @return [String, nil] Loadbalancer IP address
    def get_loadbalancer_ip
      @config && @config['loadbalancer_ip']
    end

    # Get SSH username from configuration
    #
    # @return [String] SSH username (default: 'root')
    def get_ssh_username
      (@config && @config['username']) || 'root'
    end

    # Get SSH key path from configuration
    #
    # @return [String] SSH key path (default: '~/.ssh/id_rsa')
    def get_ssh_key_path
      (@config && @config['ssh_key']) || '~/.ssh/id_rsa'
    end

    # Get token from configuration
    #
    # @return [String, nil] RKE2 token
    def get_token
      @config && @config['token']
    end

    # Check if configuration has loadbalancer
    #
    # @return [Boolean] True if loadbalancer is configured
    def has_loadbalancer?
      lb_ip = get_loadbalancer_ip
      !lb_ip.nil? && !lb_ip.empty?
    end

    # Count total nodes by role
    #
    # @param role [String] Node role ('server', 'agent', 'lb')
    # @return [Integer] Number of nodes with specified role
    def count_nodes_by_role(role)
      return 0 unless @config && @config['nodes'].is_a?(Array)

      @config['nodes'].count { |node| node['role'] == role }
    end

    # Get all nodes with specified role
    #
    # @param role [String] Node role
    # @return [Array<Hash>] Array of normalized node configurations
    def get_nodes_by_role(role)
      return [] unless @config && @config['nodes'].is_a?(Array)

      @config['nodes'].select { |node| node['role'] == role }.map do |node|
        extract_node_config(node)
      end
    end
  end
end

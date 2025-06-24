# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require 'net/ssh'
require 'net/scp'
require 'timeout'
require 'socket'
require 'fileutils'
require_relative 'logger'

module RKE2
  # SSH Helper utility class for remote operations with sudo support
  class Helper
    # SSH connection timeout in seconds
    CONNECTION_TIMEOUT = 120
    # Command execution timeout in seconds (increased for RKE2 installation)
    EXECUTION_TIMEOUT = 3600
    # File upload timeout in seconds
    UPLOAD_TIMEOUT = 120

    attr_reader :logger

    # Initialize SSH helper
    #
    # @param logger [RKE2::Logger] Logger instance for output
    # @param use_sudo [Boolean] Whether to use sudo for all operations
    def initialize(logger: nil, use_sudo: true)
      @logger = logger || RKE2::Logger.new
      @use_sudo = use_sudo
    end

    # Execute command on remote host via SSH with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param command [String] Command to execute
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional SSH options
    # @return [Hash] Result hash with success status, output, and error
    def ssh_exec(host, user, command, key_path, options = {})
      result = { success: false, output: '', error: nil, exit_code: nil }

      # Wrap command with sudo if enabled and not already using sudo
      final_command = wrap_with_sudo(command, options)

      ssh_options = build_ssh_options(key_path, options)

      # Use custom timeout if provided, otherwise use default
      execution_timeout = options[:timeout] || EXECUTION_TIMEOUT
      connection_timeout = options[:connection_timeout] || CONNECTION_TIMEOUT

      begin
        @logger.debug("Executing SSH command on #{host}", {
                        host: host,
                        user: user,
                        command: final_command.length > 100 ? "#{final_command[0..100]}..." : final_command,
                        using_sudo: @use_sudo,
                        timeout: execution_timeout
                      })

        Timeout.timeout(connection_timeout) do
          Net::SSH.start(host, user, ssh_options) do |ssh|
            output = ''
            exit_code = nil

            # Execute command with timeout
            Timeout.timeout(execution_timeout) do
              ssh.open_channel do |channel|
                channel.exec(final_command) do |_ch, success|
                  unless success
                    result[:error] = 'Command execution failed to start'
                    return result
                  end

                  # Collect stdout
                  channel.on_data do |_ch, data|
                    output += safe_encode_utf8(data)
                  end

                  # Collect stderr
                  channel.on_extended_data do |_ch, _type, data|
                    output += safe_encode_utf8(data)
                  end

                  # Get exit status
                  channel.on_request('exit-status') do |_ch, data|
                    exit_code = data.read_long
                  end
                end
              end

              ssh.loop
            end

            result[:output] = output.strip
            result[:exit_code] = exit_code
            result[:success] = exit_code == 0

            if result[:success]
              @logger.debug('SSH command completed successfully', {
                              host: host,
                              exit_code: exit_code,
                              output_length: output.length
                            })
            else
              @logger.warn('SSH command failed', {
                             host: host,
                             exit_code: exit_code,
                             output: output.strip
                           })
            end

            result
          end
        end
      rescue Net::SSH::AuthenticationFailed => e
        error_msg = "SSH authentication failed: #{e.message}"
        @logger.error(error_msg, { host: host, user: user })
        result[:error] = error_msg
        result
      rescue Net::SSH::ConnectionTimeout, Timeout::Error => e
        error_msg = "SSH connection timeout: #{e.message}"
        @logger.error(error_msg, { host: host, timeout: execution_timeout })
        result[:error] = error_msg
        result
      rescue StandardError => e
        error_msg = "SSH connection failed: #{e.message}"
        @logger.error(error_msg, { host: host, error_class: e.class.name })
        result[:error] = error_msg
        result
      end
    end

    # Test SSH connection to remote host
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional SSH options
    # @return [Boolean] True if connection successful
    def test_ssh_connection(host, user, key_path, options = {})
      @logger.debug('Testing SSH connection', { host: host, user: user })

      # Use a simple command that doesn't require sudo for connection testing
      result = ssh_exec(host, user, 'echo "connection_test"', key_path, options.merge(skip_sudo: false))

      if result[:success] && result[:output].include?('connection_test')
        @logger.success('SSH connection test passed', { host: host })
        true
      else
        @logger.error('SSH connection test failed', {
                        host: host,
                        error: result[:error] || 'Unexpected output'
                      })
        false
      end
    end

    # Test sudo access on remote host
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional SSH options
    # @return [Boolean] True if sudo access available
    def test_sudo_access(host, user, key_path, options = {})
      @logger.debug('Testing sudo access', { host: host, user: user })

      result = ssh_exec(host, user, 'whoami', key_path, options)

      if result[:success] && result[:output].strip == 'root'
        @logger.success('Sudo access confirmed', { host: host })
        true
      else
        @logger.error('Sudo access test failed', {
                        host: host,
                        output: result[:output],
                        error: result[:error]
                      })
        false
      end
    end

    # Upload file to remote host via SCP with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param local_path [String] Local file path
    # @param remote_path [String] Remote file path
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status and error
    def scp_upload(host, user, local_path, remote_path, key_path, options = {})
      result = { success: false, error: nil }

      unless File.exist?(local_path)
        result[:error] = "Local file not found: #{local_path}"
        @logger.error(result[:error])
        return result
      end

      ssh_options = build_ssh_options(key_path, options)
      temp_path = "/tmp/rke2_upload_#{Time.now.to_i}_#{rand(1000)}"

      begin
        @logger.debug('Uploading file via SCP with sudo', {
                        host: host,
                        local_path: local_path,
                        remote_path: remote_path,
                        temp_path: temp_path,
                        file_size: File.size(local_path)
                      })

        # First upload to temp location
        Timeout.timeout(UPLOAD_TIMEOUT) do
          Net::SCP.start(host, user, ssh_options) do |scp|
            scp.upload!(local_path, temp_path)
          end
        end

        # Then move to final location with sudo
        move_result = ssh_exec(host, user, "mv '#{temp_path}' '#{remote_path}'", key_path, options)

        unless move_result[:success]
          # Cleanup temp file if move failed
          ssh_exec(host, user, "rm -f '#{temp_path}'", key_path, options.merge(skip_sudo: false))
          result[:error] = "Failed to move file to final location: #{move_result[:error]}"
          @logger.error(result[:error], { host: host })
          return result
        end

        result[:success] = true
        @logger.success('File uploaded successfully with sudo', {
                          host: host,
                          remote_path: remote_path
                        })

        result
      rescue StandardError => e
        # Cleanup temp file on error
        ssh_exec(host, user, "rm -f '#{temp_path}'", key_path, options.merge(skip_sudo: false))
        error_msg = "SCP upload failed: #{e.message}"
        @logger.error(error_msg, { host: host, error_class: e.class.name })
        result[:error] = error_msg
        result
      end
    end

    # Upload file content to remote host with sudo (fallback when SCP fails)
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param content [String] File content to upload
    # @param remote_path [String] Remote file path
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status and error
    def ssh_upload_content(host, user, content, remote_path, key_path, options = {})
      temp_path = "/tmp/rke2_content_#{Time.now.to_i}_#{rand(1000)}"

      # Create directory if needed and upload content to temp location first
      commands = [
        # Create temp file without sudo
        { command: "cat > '#{temp_path}' << 'RKE2_EOF'\n#{content}\nRKE2_EOF", skip_sudo: false },
        # Create target directory with sudo
        "mkdir -p '$(dirname \"#{remote_path}\")'",
        # Move and set permissions with sudo
        "mv '#{temp_path}' '#{remote_path}'",
        "chmod 644 '#{remote_path}'"
      ]

      @logger.debug('Uploading content via SSH with sudo', {
                      host: host,
                      remote_path: remote_path,
                      temp_path: temp_path,
                      content_size: content.length
                    })

      # Execute upload commands
      commands.each_with_index do |cmd_info, index|
        if cmd_info.is_a?(Hash)
          command = cmd_info[:command]
          cmd_options = options.merge(cmd_info.reject { |k, _| k == :command })
        else
          command = cmd_info
          cmd_options = options
        end

        result = ssh_exec(host, user, command, key_path, cmd_options)

        next if result[:success]

        error_msg = "Content upload failed at step #{index + 1}: #{result[:error]}"
        @logger.error(error_msg, { host: host, step: index + 1 })

        # Cleanup temp file
        ssh_exec(host, user, "rm -f '#{temp_path}'", key_path, options.merge(skip_sudo: false))
        return { success: false, error: error_msg }
      end

      @logger.success('Content uploaded successfully via SSH with sudo', {
                        host: host,
                        remote_path: remote_path
                      })

      { success: true, error: nil }
    end

    # Download file from remote host via SCP with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param remote_path [String] Remote file path
    # @param local_path [String] Local file path
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status and error
    def scp_download(host, user, remote_path, local_path, key_path, options = {})
      result = { success: false, error: nil }
      ssh_options = build_ssh_options(key_path, options)
      temp_path = "/tmp/rke2_download_#{Time.now.to_i}_#{rand(1000)}"

      begin
        @logger.debug('Downloading file via SCP with sudo', {
                        host: host,
                        remote_path: remote_path,
                        local_path: local_path,
                        temp_path: temp_path
                      })

        # First copy to temp location with sudo
        copy_result = ssh_exec(host, user, "cp '#{remote_path}' '#{temp_path}'", key_path, options)
        unless copy_result[:success]
          result[:error] = "Failed to copy file to temp location: #{copy_result[:error]}"
          @logger.error(result[:error], { host: host })
          return result
        end

        # Change permissions to allow download
        chmod_result = ssh_exec(host, user, "chmod 644 '#{temp_path}'", key_path, options.merge(skip_sudo: false))
        @logger.warn('Failed to change temp file permissions', { host: host }) unless chmod_result[:success]

        # Create local directory if needed
        FileUtils.mkdir_p(File.dirname(local_path))

        # Download from temp location
        Timeout.timeout(UPLOAD_TIMEOUT) do
          Net::SCP.start(host, user, ssh_options) do |scp|
            scp.download!(temp_path, local_path)
          end
        end

        # Cleanup temp file
        ssh_exec(host, user, "rm -f '#{temp_path}'", key_path, options.merge(skip_sudo: false))

        result[:success] = true
        @logger.success('File downloaded successfully with sudo', {
                          host: host,
                          local_path: local_path,
                          file_size: File.size(local_path)
                        })

        result
      rescue StandardError => e
        # Cleanup temp file on error
        ssh_exec(host, user, "rm -f '#{temp_path}'", key_path, options.merge(skip_sudo: false))
        error_msg = "SCP download failed: #{e.message}"
        @logger.error(error_msg, { host: host, error_class: e.class.name })
        result[:error] = error_msg
        result
      end
    end

    # Execute multiple commands in sequence with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param commands [Array<String>] Array of commands to execute
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status, outputs, and errors
    def ssh_exec_multi(host, user, commands, key_path, options = {})
      results = []
      overall_success = true

      @logger.debug('Executing multiple SSH commands with sudo', {
                      host: host,
                      command_count: commands.length,
                      using_sudo: @use_sudo
                    })

      commands.each_with_index do |command, index|
        @logger.debug("Executing command #{index + 1}/#{commands.length}", {
                        host: host,
                        command: command.length > 50 ? "#{command[0..50]}..." : command
                      })

        result = ssh_exec(host, user, command, key_path, options)
        results << result

        next if result[:success]

        overall_success = false
        @logger.error("Command #{index + 1} failed", {
                        host: host,
                        command: command,
                        error: result[:error]
                      })

        # Stop on first failure unless continue_on_error is set
        break unless options[:continue_on_error]
      end

      {
        success: overall_success,
        results: results,
        completed_commands: results.length
      }
    end

    # Check if remote host is reachable
    #
    # @param host [String] Remote host address
    # @param port [Integer] Port to check (default: 22)
    # @param timeout [Integer] Connection timeout in seconds
    # @return [Boolean] True if host is reachable
    def host_reachable?(host, port = 22, timeout = 5)
      Timeout.timeout(timeout) do
        TCPSocket.new(host, port).close
      end
      @logger.debug('Host is reachable', { host: host, port: port })
      true
    rescue StandardError => e
      @logger.debug('Host is not reachable', {
                      host: host,
                      port: port,
                      error: e.message
                    })
      false
    end

    # Get system information from remote host with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] System information or error
    def get_system_info(host, user, key_path, options = {})
      commands = {
        hostname: 'hostname',
        os_release: 'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -s',
        kernel: 'uname -r',
        cpu_count: 'nproc',
        memory: "free -h | grep '^Mem:' | awk '{print $2}'",
        disk_space: "df -h / | tail -1 | awk '{print $2}'",
        disk_usage: "df -h / | tail -1 | awk '{print $5}'",
        load_average: "uptime | awk -F'load average:' '{print $2}' | xargs",
        processes: 'ps aux | wc -l'
      }

      system_info = {}

      commands.each do |key, command|
        result = ssh_exec(host, user, command, key_path, options)
        system_info[key] = if result[:success]
                             result[:output].strip
                           else
                             'unknown'
                           end
      end

      @logger.debug('Retrieved system information with sudo', {
                      host: host,
                      info_keys: system_info.keys
                    })

      system_info
    end

    # Install package on remote host with sudo
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param package_name [String] Package name to install
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status and error
    def install_package(host, user, package_name, key_path, options = {})
      # Detect package manager and install
      detect_cmd = <<~CMD
        if command -v apt-get >/dev/null 2>&1; then
          apt-get update && apt-get install -y #{package_name}
        elif command -v yum >/dev/null 2>&1; then
          yum install -y #{package_name}
        elif command -v dnf >/dev/null 2>&1; then
          dnf install -y #{package_name}
        elif command -v zypper >/dev/null 2>&1; then
          zypper install -y #{package_name}
        elif command -v pacman >/dev/null 2>&1; then
          pacman -S --noconfirm #{package_name}
        else
          echo "No supported package manager found" >&2
          exit 1
        fi
      CMD

      @logger.debug('Installing package with sudo', {
                      host: host,
                      package: package_name
                    })

      result = ssh_exec(host, user, detect_cmd, key_path, options)

      if result[:success]
        @logger.success('Package installed successfully', {
                          host: host,
                          package: package_name
                        })
      else
        @logger.error('Package installation failed', {
                        host: host,
                        package: package_name,
                        error: result[:error]
                      })
      end

      result
    end

    # Execute long-running command with progress reporting
    #
    # @param host [String] Remote host address
    # @param user [String] SSH username
    # @param command [String] Command to execute
    # @param key_path [String] Path to SSH private key
    # @param options [Hash] Additional options
    # @return [Hash] Result hash with success status, output, and error
    def ssh_exec_long_running(host, user, command, key_path, options = {})
      result = { success: false, output: '', error: nil, exit_code: nil }

      # Use extended timeout for long-running commands
      execution_timeout = options[:timeout] || 3600 # 1 hour default
      progress_interval = options[:progress_interval] || 30 # Progress every 30 seconds

      final_command = wrap_with_sudo(command, options)
      ssh_options = build_ssh_options(key_path, options)

      @logger.info("开始执行长时间脚本，预计需要 #{execution_timeout / 60} 分钟")
      @logger.info("每 #{progress_interval} 秒会显示进度信息")

      begin
        start_time = Time.now

        # Connect with connection timeout, then execute with execution timeout
        Net::SSH.start(host, user, ssh_options) do |ssh|
          output = ''
          exit_code = nil
          last_progress = Time.now

          # Execute command with extended timeout and progress reporting
          Timeout.timeout(execution_timeout) do
            ssh.open_channel do |channel|
              channel.exec(final_command) do |_ch, success|
                unless success
                  result[:error] = 'Command execution failed to start'
                  return result
                end

                # Collect stdout with progress reporting
                channel.on_data do |_ch, data|
                  safe_data = safe_encode_utf8(data)
                  output += safe_data

                  # Show progress every interval
                  if Time.now - last_progress >= progress_interval
                    elapsed = Time.now - start_time
                    @logger.info("脚本执行中... 已运行 #{elapsed.to_i} 秒 (#{(elapsed / 60).round(1)} 分钟)")
                    @logger.debug("最新输出: #{safe_data.strip[-100..-1] || safe_data.strip}")
                    last_progress = Time.now
                  end
                end

                # Collect stderr
                channel.on_extended_data do |_ch, _type, data|
                  output += safe_encode_utf8(data)
                end

                # Get exit status
                channel.on_request('exit-status') do |_ch, data|
                  exit_code = data.read_long
                end
              end
            end

            ssh.loop
          end

          result[:output] = output.strip
          result[:exit_code] = exit_code
          result[:success] = exit_code == 0

          elapsed = Time.now - start_time
          if result[:success]
            @logger.success("长时间脚本执行完成，耗时 #{elapsed.to_i} 秒 (#{(elapsed / 60).round(1)} 分钟)")
          else
            @logger.error("长时间脚本执行失败，耗时 #{elapsed.to_i} 秒")
            safe_output = safe_encode_utf8(output)
            @logger.debug("错误输出: #{safe_output[-500..-1] || safe_output}")
          end

          result
        end
      rescue Net::SSH::AuthenticationFailed => e
        error_msg = "SSH authentication failed: #{e.message}"
        @logger.error(error_msg, { host: host, user: user })
        result[:error] = error_msg
        result
      rescue Net::SSH::ConnectionTimeout, Timeout::Error => e
        elapsed = Time.now - start_time
        error_msg = "SSH connection timeout after #{elapsed.to_i} seconds: #{e.message}"
        @logger.error(error_msg, { host: host, timeout: execution_timeout })
        result[:error] = error_msg
        result
      rescue StandardError => e
        error_msg = "SSH connection failed: #{e.message}"
        @logger.error(error_msg, { host: host, error_class: e.class.name })
        result[:error] = error_msg
        result
      end
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

    # Wrap command with sudo if enabled
    #
    # @param command [String] Original command
    # @param options [Hash] Options that may contain skip_sudo flag
    # @return [String] Command wrapped with sudo if applicable
    def wrap_with_sudo(command, options = {})
      return command if !@use_sudo || options[:skip_sudo] || command.start_with?('sudo ')

      # For complex commands with pipes, redirects, etc., wrap the entire command
      if command.include?('|') || command.include?('>') || command.include?('<') || command.include?('&&') || command.include?('||')
        "sudo bash -c #{command.shellescape}"
      else
        "sudo #{command}"
      end
    end

    # Build SSH connection options
    #
    # @param key_path [String] Path to SSH private key
    # @param user_options [Hash] User-provided options
    # @return [Hash] SSH connection options
    def build_ssh_options(key_path, user_options = {})
      default_options = {
        keys: [key_path],
        verify_host_key: :never,
        auth_methods: ['publickey'],
        timeout: CONNECTION_TIMEOUT,
        keepalive: true,
        keepalive_interval: 60,
        compression: true,
        forward_agent: false
      }

      default_options.merge(user_options.reject do |k, _|
        %i[skip_sudo continue_on_error timeout progress_interval connection_timeout].include?(k)
      end)
    end

    # Class methods for global helper instance
    class << self
      attr_accessor :default_helper

      # Get or create default helper instance
      #
      # @return [RKE2::Helper] Default helper instance
      def instance
        @default_helper ||= new
      end

      # Configure default helper
      #
      # @param options [Hash] Helper configuration options
      def configure(**options)
        @default_helper = new(**options)
      end

      # Delegate methods to default helper
      %i[ssh_exec test_ssh_connection test_sudo_access scp_upload ssh_upload_content
         scp_download ssh_exec_multi host_reachable? get_system_info install_package].each do |method|
        define_method(method) do |*args, **kwargs|
          instance.send(method, *args, **kwargs)
        end
      end
    end
  end
end

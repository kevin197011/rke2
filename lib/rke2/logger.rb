# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require 'logger'
require 'time'
require 'json'

module RKE2
  # Logger utility class for RKE2 deployment with structured logging support
  class Logger
    # Log levels mapping
    LEVELS = {
      debug: ::Logger::DEBUG,
      info: ::Logger::INFO,
      warn: ::Logger::WARN,
      error: ::Logger::ERROR,
      fatal: ::Logger::FATAL
    }.freeze

    # Color codes for terminal output
    COLORS = {
      debug: "\033[36m",    # Cyan
      info: "\033[32m",     # Green
      warn: "\033[33m",     # Yellow
      error: "\033[31m",    # Red
      fatal: "\033[35m",    # Magenta
      reset: "\033[0m"      # Reset
    }.freeze

    # Emoji icons for different log types
    ICONS = {
      debug: '🐛',
      info: 'ℹ️',
      warn: '⚠️',
      error: '❌',
      fatal: '💀',
      success: '✅',
      loading: '⏳',
      upload: '📤',
      download: '📥',
      config: '⚙️',
      network: '🌐',
      security: '🔒',
      performance: '⚡',
      deploy: '🚀',
      system: '🔧',
      storage: '💾',
      monitor: '📊'
    }.freeze

    attr_reader :logger, :level, :output_format, :show_colors

    # Initialize logger with custom configuration
    #
    # @param output [IO, String] Output destination (STDOUT, file path, etc.)
    # @param level [Symbol, String] Log level (:debug, :info, :warn, :error, :fatal)
    # @param format [Symbol] Output format (:standard, :json, :structured)
    # @param colors [Boolean] Enable colored output for terminal
    # @param context [Hash] Default context to include in all log messages
    def initialize(output: $stdout, level: :info, format: :standard, colors: true, context: {})
      @output_format = format.to_sym
      @show_colors = colors && output.respond_to?(:tty?) && output.tty?
      @default_context = context

      @logger = ::Logger.new(output)
      @logger.level = LEVELS[level.to_sym] || ::Logger::INFO
      @logger.formatter = method(:format_message)
    end

    # Log debug message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def debug(message, context = {})
      log(:debug, message, context)
    end

    # Log info message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def info(message, context = {})
      log(:info, message, context)
    end

    # Log warning message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def warn(message, context = {})
      log(:warn, message, context)
    end

    # Log error message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def error(message, context = {})
      log(:error, message, context)
    end

    # Log fatal message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def fatal(message, context = {})
      log(:fatal, message, context)
    end

    # Log success message (special info level with success icon)
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def success(message, context = {})
      log(:info, message, context.merge(icon: :success))
    end

    # Log loading/progress message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def loading(message, context = {})
      log(:info, message, context.merge(icon: :loading))
    end

    # Log deployment related message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def deploy(message, context = {})
      log(:info, message, context.merge(icon: :deploy))
    end

    # Log system operation message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def system(message, context = {})
      log(:info, message, context.merge(icon: :system))
    end

    # Log network operation message
    #
    # @param message [String] Log message
    # @param context [Hash] Additional context information
    def network(message, context = {})
      log(:info, message, context.merge(icon: :network))
    end

    # Log with custom icon
    #
    # @param level [Symbol] Log level
    # @param message [String] Log message
    # @param icon [Symbol] Icon type
    # @param context [Hash] Additional context information
    def log_with_icon(level, message, icon, context = {})
      log(level, message, context.merge(icon: icon))
    end

    # Create a child logger with additional context
    #
    # @param context [Hash] Additional context to merge
    # @return [RKE2::Logger] New logger instance with merged context
    def with_context(context)
      new_context = @default_context.merge(context)
      self.class.new(
        output: @logger.instance_variable_get(:@logdev).dev,
        level: @logger.level,
        format: @output_format,
        colors: @show_colors,
        context: new_context
      )
    end

    # Measure execution time and log the result
    #
    # @param message [String] Operation description
    # @param level [Symbol] Log level for the result
    # @param context [Hash] Additional context
    # @yield Block to measure
    # @return [Object] Block result
    def time(message, level: :info, context: {})
      start_time = Time.now
      log(level, "🕐 Starting: #{message}", context)

      result = yield

      duration = Time.now - start_time
      log(level, "⏱️  Completed: #{message} (#{format('%.2f', duration)}s)",
          context.merge(duration_seconds: duration))

      result
    rescue StandardError => e
      duration = Time.now - start_time
      error("💥 Failed: #{message} (#{format('%.2f', duration)}s): #{e.message}",
            context.merge(duration_seconds: duration, error: e.class.name))
      raise
    end

    # Log step in a process with step number
    #
    # @param step [Integer] Step number
    # @param total [Integer] Total steps
    # @param message [String] Step description
    # @param context [Hash] Additional context
    def step(step, total, message, context = {})
      prefix = "[#{step}/#{total}]"
      log(:info, "#{prefix} #{message}", context.merge(step: step, total_steps: total))
    end

    private

    # Internal logging method
    #
    # @param level [Symbol] Log level
    # @param message [String] Log message
    # @param context [Hash] Context information
    def log(level, message, context = {})
      return unless @logger.send("#{level}?")

      full_context = @default_context.merge(context)
      @logger.send(level) { { message: message, context: full_context } }
    end

    # Format log message based on configured format
    #
    # @param severity [String] Log severity
    # @param timestamp [Time] Log timestamp
    # @param progname [String] Program name
    # @param msg [Hash, String] Message data
    # @return [String] Formatted message
    def format_message(severity, timestamp, progname, msg)
      case @output_format
      when :json
        format_json(severity, timestamp, progname, msg)
      when :structured
        format_structured(severity, timestamp, progname, msg)
      else
        format_standard(severity, timestamp, progname, msg)
      end
    end

    # Format message in JSON format
    #
    # @param severity [String] Log severity
    # @param timestamp [Time] Log timestamp
    # @param progname [String] Program name
    # @param msg [Hash, String] Message data
    # @return [String] JSON formatted message
    def format_json(severity, timestamp, progname, msg)
      data = {
        timestamp: timestamp.iso8601,
        level: severity.downcase,
        message: extract_message(msg),
        context: extract_context(msg)
      }
      data[:progname] = progname if progname
      "#{JSON.generate(data)}\n"
    end

    # Format message in structured format
    #
    # @param severity [String] Log severity
    # @param timestamp [Time] Log timestamp
    # @param progname [String] Program name
    # @param msg [Hash, String] Message data
    # @return [String] Structured formatted message
    def format_structured(severity, timestamp, _progname, msg)
      message = extract_message(msg)
      context = extract_context(msg)

      parts = [
        format_timestamp(timestamp),
        format_level(severity),
        format_icon(context[:icon] || severity.downcase.to_sym),
        message
      ]

      parts << format_context_details(context) unless context.empty?
      "#{parts.join(' ')}\n"
    end

    # Format message in standard format (similar to current project style)
    #
    # @param severity [String] Log severity
    # @param timestamp [Time] Log timestamp
    # @param progname [String] Program name
    # @param msg [Hash, String] Message data
    # @return [String] Standard formatted message
    def format_standard(severity, _timestamp, _progname, msg)
      message = extract_message(msg)
      context = extract_context(msg)

      icon = ICONS[context[:icon]] || ICONS[severity.downcase.to_sym] || ''
      colored_message = apply_color(severity.downcase.to_sym, "#{icon} #{message}")

      "#{colored_message}\n"
    end

    # Extract message from log data
    #
    # @param msg [Hash, String] Message data
    # @return [String] Extracted message
    def extract_message(msg)
      case msg
      when Hash
        msg[:message] || msg['message'] || msg.to_s
      else
        msg.to_s
      end
    end

    # Extract context from log data
    #
    # @param msg [Hash, String] Message data
    # @return [Hash] Extracted context
    def extract_context(msg)
      case msg
      when Hash
        context = msg[:context] || msg['context'] || {}
        # Remove message and context keys to avoid duplication
        msg.reject { |k, _| [:message, 'message', :context, 'context'].include?(k) }
           .merge(context)
      else
        {}
      end
    end

    # Format timestamp
    #
    # @param timestamp [Time] Timestamp
    # @return [String] Formatted timestamp
    def format_timestamp(timestamp)
      "[#{timestamp.strftime('%Y-%m-%d %H:%M:%S')}]"
    end

    # Format log level
    #
    # @param severity [String] Log severity
    # @return [String] Formatted level
    def format_level(severity)
      level_str = severity.ljust(5)
      apply_color(severity.downcase.to_sym, level_str)
    end

    # Format icon
    #
    # @param icon_type [Symbol] Icon type
    # @return [String] Icon string
    def format_icon(icon_type)
      ICONS[icon_type] || ''
    end

    # Format context details
    #
    # @param context [Hash] Context data
    # @return [String] Formatted context
    def format_context_details(context)
      return '' if context.empty?

      details = context.reject { |k, _| k == :icon }
                       .map { |k, v| "#{k}=#{v}" }
                       .join(' ')

      "[#{details}]"
    end

    # Apply color to text if colors are enabled
    #
    # @param level [Symbol] Log level for color selection
    # @param text [String] Text to colorize
    # @return [String] Colorized or plain text
    def apply_color(level, text)
      return text unless @show_colors

      color = COLORS[level] || COLORS[:reset]
      "#{color}#{text}#{COLORS[:reset]}"
    end

    # Class methods for global logger instance
    class << self
      attr_accessor :default_logger

      # Get or create default logger instance
      #
      # @return [RKE2::Logger] Default logger instance
      def instance
        @default_logger ||= new
      end

      # Configure default logger
      #
      # @param options [Hash] Logger configuration options
      def configure(**options)
        @default_logger = new(**options)
      end

      # Delegate methods to default logger
      %i[debug info warn error fatal success loading
         deploy system network log_with_icon time step].each do |method|
        define_method(method) do |*args, **kwargs, &block|
          instance.send(method, *args, **kwargs, &block)
        end
      end
    end
  end
end

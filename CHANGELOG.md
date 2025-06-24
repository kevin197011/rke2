# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Gemspec configuration for proper gem packaging
- RuboCop configuration for code style consistency
- Comprehensive Rakefile with development tasks
- Binary executable in `bin/rke2` for CLI usage
- Development dependencies for code quality tools

### Changed
- Updated Gemfile to use gemspec for dependency management
- Improved project structure following Ruby gem conventions
- Enhanced .gitignore with comprehensive ignore rules

## [0.1.0] - 2025-01-XX

### Added
- 🎉 Initial release of RKE2 deployment tool
- 🏗️ Complete RKE2 cluster deployment functionality
- 🔧 Modular architecture with 10 core modules:
  - `bootstrap.rb` - System initialization and performance optimization
  - `proxy.rb` - HAProxy load balancer configuration
  - `server.rb` - RKE2 Server (control plane) deployment
  - `agent.rb` - RKE2 Agent (worker) deployment
  - `finalizer.rb` - Cluster finalization and tool configuration
  - `deploy.rb` - Deployment orchestration and flow management
  - `config.rb` - Configuration management
  - `helper.rb` - SSH and system operation utilities
  - `logger.rb` - Advanced logging system
  - `version.rb` - Version information
- 🎛️ Interactive CLI with multiple deployment modes:
  - Complete deployment (bootstrap + HAProxy + Server + Agent + tools)
  - Quick deployment (Server nodes only)
  - Server deployment (bootstrap + HAProxy + Server)
  - Custom deployment (selective component deployment)
  - Bootstrap only (system optimization)
- 🚀 System optimization features:
  - Time synchronization (Hong Kong timezone)
  - Swap disabling
  - Kernel module loading (overlay, br_netfilter, etc.)
  - System parameter optimization
  - System limits adjustment
  - Firewall configuration
  - Memory optimization (THP disabling)
- 🌐 HAProxy load balancer automatic configuration
- 🔍 Cluster health verification and status reporting
- ⚡ Intelligent restart management with status verification
- 📝 Comprehensive logging system with multiple formats
- 🔧 SSH operation utilities with error handling
- 📋 Flexible YAML-based configuration management
- 🛠️ Automatic kubectl, Helm, K9s tool configuration

### Core Dependencies
- `net-ssh` ~> 7.0 - SSH connection and command execution
- `net-scp` ~> 4.0 - SCP file transfer functionality

### Development Features
- RSpec testing framework setup
- RuboCop code style checking
- YARD documentation generation
- Pry debugging tools
- Performance profiling utilities

---

## Development

### Adding a new feature
1. Create a feature branch
2. Implement the feature with tests
3. Update this CHANGELOG.md
4. Update version in `lib/rke2/version.rb` if needed
5. Submit a pull request

### Release process
1. Update version in `lib/rke2/version.rb`
2. Update CHANGELOG.md with release date
3. Create git tag: `git tag v0.1.0`
4. Build and publish gem: `rake release`
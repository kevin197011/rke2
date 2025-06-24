# RKE2 Kubernetes 集群部署工具

一个用于自动化部署和管理 RKE2 Kubernetes 集群的 Ruby 工具库。

## 功能特性

- 🚀 **自动化系统初始化**: 自动配置系统参数和性能优化
- 🔄 **智能重启管理**: 初始化完成后自动重启并等待节点恢复
- 🔧 **SSH 远程操作**: 支持批量远程命令执行和文件传输
- 📊 **实时日志记录**: 多格式日志输出和进度跟踪
- ⚡ **性能优化**: 内核参数、系统限制、网络配置优化
- 🛡️ **安全配置**: sudo 权限管理和连接验证
- 📋 **配置管理**: YAML 配置文件支持
- 🔍 **状态验证**: 初始化后自动验证系统状态

## 系统要求

- Ruby 2.7+
- SSH 密钥认证
- 目标节点需要 sudo 权限

## 安装

```bash
git clone https://github.com/your-username/rke2.git
cd rke2
bundle install
```

## 配置

创建 `config.yml` 配置文件：

```yaml
token: rke2Secret123456
loadbalancer_ip: 1.1.1.31
username: devops
ssh_key: ~/.ssh/id_rsa

nodes:
  - name: master-01
    ip: 1.1.1.11
    role: server
  - name: master-02
    ip: 1.1.1.12
    role: server
  - name: master-03
    ip: 1.1.1.13
    role: server

  - name: worker-01
    ip: 1.1.1.21
    role: agent
  - name: worker-02
    ip: 1.1.1.22
    role: agent
  - name: worker-03
    ip: 1.1.1.23
    role: agent

  - name: lb-01
    ip: 1.1.1.31
    role: lb
```

## 使用方法

### 1. 基本使用

```ruby
require 'rke2'

# 初始化所有节点（包含重启）
RKE2.bootstrap

# 初始化所有节点但不重启
RKE2.bootstrap(reboot: false)

# 初始化单个节点（包含重启）
RKE2.bootstrap_node('master-01')

# 初始化单个节点但不重启
RKE2.bootstrap_node('master-01', reboot: false)
```

### 2. 使用自定义配置

```ruby
# 使用自定义配置文件
RKE2.bootstrap('my-config.yml', reboot: true)

# 使用自定义日志器
logger = RKE2::Logger.new(format: :json)
RKE2.bootstrap('config.yml', reboot: true, logger: logger)
```

### 3. 使用测试脚本

```bash
# 交互式测试脚本（支持重启功能）
./test_bootstrap_reboot

# 直接运行脚本
ruby run
```

### 4. 重启功能详解

新版本支持智能重启管理：

**阶段 1: 系统初始化**
- 时间同步配置
- 时区设置为香港时区
- 禁用 Swap
- 内核模块加载
- 系统参数优化
- 防火墙配置
- 系统工具安装

**阶段 2: 自动重启**（可选）
- 发送重启命令到所有节点
- 等待节点离线（最多 2 分钟）
- 等待节点恢复在线（最多 5 分钟）
- 验证重启后系统状态

**重启验证内容**：
- 主机名设置
- 时区配置验证
- Swap 禁用状态
- 内核模块加载
- 透明大页禁用

## 日志系统

### Logger 功能

```ruby
# 创建不同格式的日志器
logger = RKE2::Logger.new(format: :standard)  # 标准格式
logger = RKE2::Logger.new(format: :structured) # 结构化格式
logger = RKE2::Logger.new(format: :json)      # JSON 格式

# 日志级别
logger.debug('调试信息')
logger.info('一般信息')
logger.success('成功信息')
logger.warning('警告信息')
logger.error('错误信息')
logger.fatal('致命错误')

# 特殊日志方法
logger.deploy('部署开始')      # 部署相关
logger.loading('处理中...')    # 加载状态
logger.step(1, 5, '步骤1')     # 步骤进度

# 时间测量
logger.time('操作名称') do
  # 执行操作
end
```

### SSH Helper 功能

```ruby
helper = RKE2::Helper.new

# 连接测试
helper.test_ssh_connection(ip, username, ssh_key)
helper.test_sudo_access(ip, username, ssh_key)
helper.host_reachable?(ip, port, timeout)

# 命令执行
result = helper.ssh_exec(ip, username, command, ssh_key)
results = helper.ssh_exec_multiple(ip, username, commands, ssh_key)

# 文件操作
helper.ssh_upload_file(ip, username, local_path, remote_path, ssh_key)
helper.ssh_upload_content(ip, username, content, remote_path, ssh_key)
helper.ssh_download_file(ip, username, remote_path, local_path, ssh_key)

# 系统信息
system_info = helper.get_system_info(ip, username, ssh_key)
helper.install_packages(ip, username, packages, ssh_key)
```

## 系统优化内容

### 内核优化
- 加载必要内核模块（overlay, br_netfilter, ip_vs 等）
- 网络参数优化（bridge-nf-call, ip_forward 等）
- 性能调优（TCP 缓冲区、连接队列等）

### 时间和时区配置
- 自动配置时间同步服务（chrony 或 systemd-timesyncd）
- 设置时区为 Asia/Hong_Kong（香港时区）
- 同步硬件时钟

### 系统限制
- 文件描述符限制：1048576
- 进程数限制：1048576
- 内存锁定：unlimited
- 核心转储：unlimited

### 内存优化
- 禁用 Swap
- 禁用透明大页
- 虚拟内存参数调优

### 安全配置
- 防火墙配置
- SSH 安全设置
- sudo 权限验证

## 错误处理

```ruby
begin
  result = RKE2.bootstrap
  puts "初始化成功！" if result
rescue RKE2::Error => e
  puts "RKE2 错误: #{e.message}"
rescue StandardError => e
  puts "系统错误: #{e.message}"
end
```

## 部署流程

1. **准备阶段**
   - 配置 SSH 密钥认证
   - 创建配置文件
   - 验证网络连通性

2. **初始化阶段**
   ```bash
   ./test_bootstrap_reboot
   # 选择 "1. 初始化所有节点并重启"
   ```

3. **验证阶段**
   - 检查系统优化是否生效
   - 验证服务状态
   - 确认网络配置

4. **部署 RKE2**（后续功能）
   - 安装 RKE2 二进制文件
   - 配置集群
   - 部署应用

## 安全考虑

- 所有操作都通过 sudo 执行，确保权限安全
- SSH 密钥认证，避免密码传输
- 连接超时和重试机制
- 详细的操作日志记录

## 故障排除

### 常见问题

1. **SSH 连接失败**
   ```bash
   # 检查 SSH 密钥
   ssh -i ~/.ssh/id_rsa user@host

   # 检查网络连通性
   ping host
   telnet host 22
   ```

2. **sudo 权限问题**
   ```bash
   # 确保用户有 sudo 权限
   sudo visudo
   # 添加: username ALL=(ALL) NOPASSWD:ALL
   ```

3. **重启超时**
   - 检查节点是否正常启动
   - 验证网络配置
   - 查看系统日志

4. **系统优化验证失败**
   ```bash
   # 手动检查关键配置
   cat /proc/swaps                    # 检查 swap
   lsmod | grep overlay              # 检查内核模块
   sysctl net.bridge.bridge-nf-call-iptables  # 检查网络参数
   ```

## 开发

### 运行测试

```bash
# 连接测试
./test_bootstrap_reboot
# 选择 "5. 测试连接"

# 单节点测试
./test_bootstrap_reboot
# 选择 "3. 初始化单个节点并重启"
```

### 调试模式

```ruby
# 启用调试日志
logger = RKE2::Logger.new(level: :debug)
RKE2.bootstrap(logger: logger)
```

## 贡献

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 更新日志

### v1.1.0 (最新)
- ✨ 新增自动重启功能
- ✨ 重启后状态验证
- ✨ 智能等待机制
- ✨ 重启进度跟踪
- 🔧 优化错误处理
- 📚 完善文档

### v1.0.0
- 🎉 初始版本发布
- ✨ 系统初始化功能
- ✨ SSH 远程操作
- ✨ 日志系统
- ✨ 配置管理

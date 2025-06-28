# RKE2
```
        __          ________
_______|  | __ ____ \_____  \
\_  __ \  |/ // __ \ /  ____/
 |  | \/    <\  ___//       \
 |__|  |__|_ \\___  >_______ \
            \/    \/        \/
          🛠️ RKE2 Kubernetes Cluster Automation Tool
```

# RKE2 Kubernetes 集群自动化部署工具

一个功能完整的 RKE2 Kubernetes 集群自动化部署和管理工具，采用模块化架构设计，支持完整的集群生命周期管理。

## ✨ 功能特性

### 🚀 核心功能
- **🏗️ 完整集群部署**: 从系统初始化到集群就绪的一站式解决方案
- **🔧 模块化架构**: 清晰的职责分离，便于扩展和维护
- **📋 多种部署模式**: 完整部署、快速部署、服务器部署、自定义部署
- **🎛️ 交互式 CLI**: 直观的命令行界面，支持交互式和脚本化操作
- **⚡ 智能重启管理**: 自动重启和状态验证，确保系统配置生效

### 🔄 部署流程管理
- **系统初始化**: 性能优化、内核参数调整、安全配置
- **负载均衡**: HAProxy 自动配置和部署
- **RKE2 Server**: 高可用 Kubernetes 控制平面部署
- **RKE2 Agent**: Worker 节点自动加入集群
- **工具配置**: kubectl、Helm、K9s 自动配置

### 🛠️ 运维功能
- **📊 实时监控**: 部署进度跟踪和状态验证
- **🔍 集群验证**: 自动验证集群健康状态
- **📝 详细日志**: 多格式日志输出，支持调试模式
- **🔒 安全管理**: SSH 密钥认证，权限验证
- **🌐 网络配置**: 防火墙、网络参数自动配置

## 📁 项目架构

```
rke2/
├── lib/rke2/
│   ├── bootstrap.rb     # 系统初始化模块
│   ├── proxy.rb         # HAProxy 负载均衡配置
│   ├── server.rb        # RKE2 Server 节点部署
│   ├── agent.rb         # RKE2 Agent 节点部署
│   ├── finalizer.rb     # 集群最终配置和验证
│   ├── deploy.rb        # 部署编排和流程管理
│   ├── config.rb        # 配置管理
│   ├── helper.rb        # SSH 和系统操作工具
│   ├── logger.rb        # 日志系统
│   └── version.rb       # 版本信息
├── run                  # CLI 主程序
├── config.yml           # 配置文件
└── config.yml.sample   # 配置示例
```

## 📋 系统要求

- **Ruby**: 2.7+ (推荐 3.0+)
- **操作系统**: Linux (Ubuntu 20.04+, CentOS 7+, RHEL 8+)
- **网络**: SSH 密钥认证，目标节点需要 sudo 权限
- **资源**: 推荐每个节点至少 2CPU/4GB 内存

## 🚀 快速开始

### 1. 安装

```bash
git clone https://github.com/kevin197011/rke2.git
cd rke2
bundle install
```

### 2. 配置

创建 `config.yml` 配置文件（参考 `config.yml.sample`）：

```yaml
# RKE2 集群配置
token: rke2Secret123456              # 集群认证令牌
loadbalancer_ip: 192.168.1.100      # 负载均衡器 IP
username: devops                     # SSH 用户名
ssh_key: ~/.ssh/id_rsa              # SSH 私钥路径

# 节点配置
nodes:
  # Server 节点 (控制平面)
  - name: master-01
    ip: 192.168.1.10
    role: server
  - name: master-02
    ip: 192.168.1.11
    role: server
  - name: master-03
    ip: 192.168.1.12
    role: server

  # Agent 节点 (工作节点)
  - name: worker-01
    ip: 192.168.1.20
    role: agent
  - name: worker-02
    ip: 192.168.1.21
    role: agent

  # 负载均衡器
  - name: lb-01
    ip: 192.168.1.100
    role: lb
```

### 3. 部署集群

```bash
# 交互式部署
./run

# 一键完整部署
./run deploy

# 快速部署 (仅 Server 节点)
./run quick

# 仅系统初始化
./run bootstrap
```

## 🎮 CLI 使用指南

### 命令行模式

```bash
# 基本命令
./run                           # 交互式菜单
./run deploy                    # 完整部署
./run quick                     # 快速部署
./run ha                        # 高可用部署
./run servers                   # 服务器部署
./run bootstrap                 # 系统初始化
./run help                      # 帮助信息
./run version                   # 版本信息

# 调试模式
./run deploy --debug            # 启用详细调试输出
DEBUG=1 ./run deploy            # 通过环境变量启用调试

# 特殊选项
./run bootstrap --no-reboot     # 系统初始化但不自动重启
```

### 交互式菜单

```
📋 请选择部署模式:
  1. 🏢 完整部署 (系统初始化 + HAProxy + Server + Agent + 配置工具)
  2. ⚡ 快速部署 (仅 Server 节点 + 配置工具)
  3. 🎛️  服务器部署 (系统初始化 + HAProxy + Server + 配置工具)
  4. 🔧 自定义部署 (选择性跳过组件)
  5. 🚀 系统初始化 (仅执行性能优化)
  6. ℹ️  配置信息预览
  7. ❓ 帮助信息
  0. 🚪 退出
```

## 📚 API 使用

### Ruby API

```ruby
require 'rke2'

# 使用默认配置
RKE2::Deploy.run_full_with_bootstrap('config.yml')

# 使用自定义日志器
logger = RKE2::Logger.new(level: :debug)
RKE2::Deploy.run_quick('config.yml', logger: logger)

# 自定义部署选项
RKE2::Deploy.run(
  'config.yml',
  logger: logger,
  skip_bootstrap: false,
  skip_haproxy: false,
  skip_agents: false,
  skip_finalization: false,
  auto_reboot: true
)
```

### 模块化使用

```ruby
# 系统初始化
bootstrap = RKE2::Bootstrap.new('config.yml', logger: logger)
bootstrap.initialize_all_nodes

# 负载均衡配置
proxy = RKE2::Proxy.new('config.yml', logger: logger)
proxy.configure_all_loadbalancers

# RKE2 部署
server = RKE2::Server.new('config.yml', logger: logger)
server.deploy_all_servers

agent = RKE2::Agent.new('config.yml', logger: logger)
agent.deploy_all_agents

# 最终配置
finalizer = RKE2::Finalizer.new('config.yml', logger: logger)
finalizer.finalize_cluster
```

## 📊 部署模式详解

### 🏢 完整部署 (deploy)
最全面的部署模式，包含所有组件：
1. **系统初始化**: 性能优化、内核参数、安全配置
2. **HAProxy 部署**: 负载均衡器配置
3. **RKE2 Server**: 控制平面节点部署
4. **RKE2 Agent**: 工作节点部署
5. **工具配置**: kubectl、Helm、K9s 配置
6. **集群验证**: 健康状态检查

### ⚡ 快速部署 (quick)
适用于测试环境的轻量级部署：
- 跳过系统初始化
- 跳过 HAProxy 配置
- 仅部署 Server 节点
- 配置基本工具

### 🎛️ 服务器部署 (servers)
适用于分阶段部署：
- 包含系统初始化
- 包含 HAProxy 配置
- 仅部署 Server 节点
- 稍后手动添加 Agent 节点

### 🔧 自定义部署 (custom)
完全可控的部署模式：
- 可选择跳过任意组件
- 灵活的重启策略
- 适用于特殊环境需求

## 🛠️ 系统优化详情

### 🔧 内核和网络优化
```bash
# 内核模块
overlay, br_netfilter, ip_vs, ip_vs_rr, ip_vs_wrr, ip_vs_sh, nf_conntrack

# 网络参数
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
```

### ⏰ 时间和时区配置
- **时区**: Asia/Hong_Kong (香港时区)
- **时间同步**: chrony 或 systemd-timesyncd
- **硬件时钟**: 自动同步

### 💾 系统限制优化
```bash
# /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
* soft memlock unlimited
* hard memlock unlimited
```

### 🚫 Swap 和内存优化
- 完全禁用 Swap
- 禁用透明大页 (THP)
- 虚拟内存参数调优

## 📝 日志系统

### Logger 功能

```ruby
# 创建日志器
logger = RKE2::Logger.new(
  level: :info,           # 日志级别: :debug, :info, :warning, :error, :fatal
  format: :standard       # 格式: :standard, :structured, :json
)

# 基础日志方法
logger.debug('调试信息')
logger.info('一般信息')
logger.success('成功操作')
logger.warning('警告信息')
logger.error('错误信息')
logger.fatal('致命错误')

# 特殊日志方法
logger.deploy('🚀 开始部署')
logger.loading('⏳ 处理中...')
logger.step(1, 5, '步骤 1/5')
logger.network('🌐 网络信息')

# 带图标的日志
logger.log_with_icon(:info, '消息内容', :rocket)

# 时间测量
logger.time('操作名称') do
  # 执行耗时操作
end
```

### 日志级别说明
- **debug**: 详细的调试信息，包含执行细节
- **info**: 一般信息，部署进度提示
- **success**: 成功完成的操作
- **warning**: 警告信息，可能需要注意
- **error**: 错误信息，操作失败
- **fatal**: 致命错误，程序退出

## 🔧 SSH Helper 工具

```ruby
helper = RKE2::Helper.new(logger: logger)

# 连接测试
helper.test_ssh_connection(ip, username, ssh_key, timeout: 30)
helper.test_sudo_access(ip, username, ssh_key)
helper.host_reachable?(ip, port: 22, timeout: 5)

# 命令执行
result = helper.ssh_exec(ip, username, command, ssh_key, timeout: 60)
results = helper.ssh_exec_multiple(ip, username, commands, ssh_key)

# 文件操作
helper.ssh_upload_file(ip, username, local_path, remote_path, ssh_key)
helper.ssh_upload_content(ip, username, content, remote_path, ssh_key)
helper.ssh_download_file(ip, username, remote_path, local_path, ssh_key)

# 系统操作
helper.reboot_and_wait(ip, username, ssh_key, wait_timeout: 300)
helper.wait_for_host_recovery(ip, username, ssh_key, timeout: 300)
system_info = helper.get_system_info(ip, username, ssh_key)

# 包管理
helper.install_packages(ip, username, packages, ssh_key)
helper.update_system(ip, username, ssh_key)
```

## 📊 集群验证

部署完成后，工具会自动执行以下验证：

### ✅ 基础验证
- 节点连接状态
- RKE2 服务状态
- kubectl 配置正确性

### 🔍 集群健康检查
- 节点 Ready 状态
- 系统 Pod 运行状态
- API Server 可访问性
- 集群版本信息

### 📋 验证报告
```
📊 集群状态验证结果
🔍 集群基本信息:
  Kubernetes 版本: v1.28.2+rke2r1
  集群服务 IP: 10.43.0.1
  节点总数: 5
  系统 Pod 数: 12

🖥️ 节点详情:
  master-01 (192.168.1.10): Ready
  master-02 (192.168.1.11): Ready
  master-03 (192.168.1.12): Ready
  worker-01 (192.168.1.20): Ready
  worker-02 (192.168.1.21): Ready

✅ 集群健康状态: 正常
```

## 🔧 故障排除

### 常见问题

#### 1. SSH 连接失败
```bash
# 检查 SSH 密钥权限
chmod 600 ~/.ssh/id_rsa

# 测试 SSH 连接
ssh -i ~/.ssh/id_rsa user@host

# 检查防火墙
sudo ufw status
sudo firewall-cmd --list-all
```

#### 2. sudo 权限问题
```bash
# 配置无密码 sudo
echo "username ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/username
```

#### 3. 重启超时
- 检查节点硬件状态
- 验证网络连接
- 查看系统启动日志

#### 4. 集群验证失败
```bash
# 手动检查 RKE2 服务
sudo systemctl status rke2-server
sudo systemctl status rke2-agent

# 查看 RKE2 日志
sudo journalctl -u rke2-server -f
sudo journalctl -u rke2-agent -f

# 检查 kubectl 配置
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
kubectl get nodes
```

### 调试模式

启用详细日志以获取更多信息：

```bash
# 环境变量方式
DEBUG=1 ./run deploy

# 命令行参数方式
./run deploy --debug

# 在 Ruby 代码中
logger = RKE2::Logger.new(level: :debug)
```

## 🎯 后续操作

部署成功后，可以执行以下操作：

### 🔑 访问集群
```bash
# SSH 登录到任意 Server 节点
ssh -i ~/.ssh/id_rsa devops@192.168.1.10

# 设置 kubectl 环境
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
# 或者使用用户配置
export KUBECONFIG=/root/.kube/config
```

### 📋 集群管理
```bash
# 查看节点状态
kubectl get nodes -o wide

# 查看系统 Pod
kubectl get pods -A

# 查看集群信息
kubectl cluster-info

# 部署测试应用
kubectl create deployment nginx --image=nginx
kubectl expose deployment nginx --port=80 --type=NodePort
```

### 🛠️ 管理工具
```bash
# 启动 K9s (如果已安装)
k9s

# 使用 Helm (如果已安装)
helm list -A
helm repo list

# 查看自动生成的管理脚本
ls -la ~/cluster-*.sh ~/helm-*.sh
```

### 🌐 访问信息
- **Kubernetes API**: `https://[loadbalancer_ip]:6443`
- **RKE2 注册服务**: `https://[loadbalancer_ip]:9345`
- **HAProxy 统计**: `http://[loadbalancer_ip]:8404/stats`

## 📈 性能调优建议

### 🖥️ 硬件配置
- **Server 节点**: 至少 4CPU/8GB 内存/50GB 存储
- **Agent 节点**: 至少 2CPU/4GB 内存/20GB 存储
- **网络**: 千兆网络，低延迟

### 🔧 系统优化
- 使用 SSD 存储
- 禁用不必要的服务
- 优化网络参数
- 配置合适的时间同步

### 📊 监控建议
考虑部署以下监控组件：
- Prometheus + Grafana
- Node Exporter
- kube-state-metrics
- AlertManager

## 🔄 更新和维护

### 版本升级
```bash
# 备份当前配置
cp config.yml config.yml.backup

# 拉取最新代码
git pull origin main

# 更新依赖
bundle install

# 重新部署（如果需要）
./run deploy
```

### 配置更新
修改 `config.yml` 后，可以重新运行特定组件：
```bash
./run bootstrap      # 仅更新系统配置
./run servers        # 重新部署 Server 节点
```

## 🤝 贡献指南

欢迎贡献代码和建议！

### 开发环境设置
```bash
# Fork 并克隆项目
git clone https://github.com/kevin197011/rke2.git
cd rke2

# 安装开发依赖
bundle install

# 创建功能分支
git checkout -b feature/your-feature-name
```

### 代码规范
- 遵循 Ruby 编码规范
- 添加适当的注释和文档
- 编写测试用例
- 更新相关文档

### 提交流程
1. Fork 项目
2. 创建功能分支
3. 编写代码和测试
4. 提交变更 (`git commit -m 'Add amazing feature'`)
5. 推送到分支 (`git push origin feature/your-feature-name`)
6. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📚 相关资源

- **RKE2 官方文档**: https://docs.rke2.io/
- **Kubernetes 文档**: https://kubernetes.io/docs/
- **HAProxy 文档**: https://www.haproxy.org/download/2.4/doc/
- **项目问题跟踪**: https://github.com/kevin197011/rke2/issues

## 🏷️ 版本历史

### v0.1.0 (当前版本)
- 🎉 初始版本发布
- ✨ 完整的 RKE2 集群部署功能
- ✨ 模块化架构设计
- ✨ CLI 工具和交互式界面
- ✨ 系统初始化和性能优化
- ✨ HAProxy 负载均衡配置
- ✨ Server/Agent 节点部署
- ✨ kubectl/Helm/K9s 工具配置
- ✨ 集群状态验证
- ✨ 智能重启和状态检查
- ✨ 详细的日志系统
- ✨ SSH 远程操作工具
- ✨ 灵活的配置管理

---

**🎯 目标**: 让 RKE2 集群部署变得简单、可靠、高效！

如有问题或建议，欢迎创建 Issue 或 Pull Request。

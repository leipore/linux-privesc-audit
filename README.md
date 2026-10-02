# linux-privesc-audit

Linux 本地提权审计工具。通过模块化采集器 + 规则引擎, 从当前用户信息出发, 系统化枚举常见提权向量, 输出可读的文本报告与结构化 JSON 报告。

## 特性

- **模块化架构**: 采集器 (`collectors/`)、规则引擎 (`rules/`)、输出 (`output/`) 三层解耦
- **只读采集**: 默认不执行任何提权利用, 仅做枚举与判定
- **纯标准库**: 无第三方依赖, 目标机直接 `python3` 运行
- **可扩展**: 新增检测项只需在对应目录添加模块并注册

## 目录结构
linux-privesc-audit/
├── main.py # 入口: 编排采集 → 分析 → 输出
├── collectors/ # 数据采集层
│ ├── system.py # 系统信息 (内核/发行版)
│ ├── users.py # 用户与组
│ ├── sudo.py # sudo 权限
│ ├── suid.py # SUID/SGID 文件
│ ├── capabilities.py # Linux Capabilities
│ ├── filesystem.py # 全局可写文件/关键路径
│ ├── cron.py # Cron 计划任务
│ ├── systemd.py # systemd 单元与定时器
│ ├── processes.py # 进程与环境变量
│ ├── network.py # 网络监听/接口/防火墙
│ ├── credentials.py # history/密钥/配置/备份
│ ├── containers.py # Docker/Podman/LXC 与危险组
│ ├── kubernetes.py # K8s ServiceAccount/kubeconfig
│ ├── kernel.py # 内核版本与 CVE 提示
│ ├── nfs.py # NFS 导出/挂载
│ └── acl.py # 扩展 ACL
├── rules/ # 规则引擎层
│ ├── sudo_rules.py
│ ├── suid_rules.py
│ ├── capability_rules.py
│ ├── cron_rules.py
│ └── systemd_rules.py
├── output/
│ ├── json_report.py
│ └── text_report.py
└── README.md




## 快速开始

```bash
# 完整审计, 输出文本报告
python3 main.py

# 完整审计并保存 JSON
python3 main.py -o report.json

# 跳过耗时较长的采集器
python3 main.py --skip suid,filesystem,acl,credentials

# 仅检查特定模块
python3 main.py --only sudo,suid,capabilities,cron

# 列出所有可用采集器
python3 main.py --list

# 只输出 JSON (适合管道)
python3 main.py --quiet -o report.json
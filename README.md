
# FastWinLog - 轻量级Windows 事件日志分析工具

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg )
![Python](https://img.shields.io/badge/python-3.12+-green.svg )
![React](https://img.shields.io/badge/react-18.2-61dafb.svg )
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg )

**智能解析 · AI 辅助 · 上下文知识库 · 安全告警分析 · 深度统计**

[WEB日志分析工具链接](https://github.com/vam876/FastWLAT) | [Linux日志分析工具链接](https://github.com/vam876/FastLinLog)

</div>

- **最新版本**: 1.0.0
- **更新日期**: 2026/04/28
- **下载地址**:  [https://github.com/vam876/FastWinLog/releases/tag/v1.0.0](https://github.com/vam876/FastWinLog/releases/tag/v1.0.0)

---

## 功能特性
<img width="1613" height="1008" alt="image" src="https://github.com/user-attachments/assets/3cb39203-838f-4415-9a4d-3f5113477d26" />

### 软件架构

#### 技术栈

**前端**
- React 18 + TypeScript
- Vite 5.0 (构建工具)
- CSS Modules (样式隔离)
  
**后端**
- Python 3.12
- WebView (桌面容器)
- libevtx-python (EVTX 解析)
- SQLite (缓存数据库)

#### 项目目录结构

```
FastWinLog/
├── backend/                      # Python 后端
│   ├── api/                     # API 接口层
│   │   ├── main_api.py         # 主 API 路由
│   │   └── __init__.py
│   ├── services/                # 业务逻辑层
│   │   ├── alert_service.py    # 告警服务
│   │   ├── cache_service.py    # 缓存服务
│   │   ├── event_service.py    # 事件处理服务
│   │   ├── log_service.py      # 日志服务
│   │   ├── search_service.py   # 搜索服务
│   │   ├── statistics_service.py # 统计服务
│   │   └── __init__.py
│   ├── repositories/            # 数据访问层
│   │   ├── evtx_repository.py  # EVTX 文件访问
│   │   ├── memory_repository.py # 内存数据访问
│   │   ├── sqlite_repository.py # SQLite 数据访问
│   │   └── __init__.py
│   ├── core/                    # 核心模块
│   │   ├── alert_baselines.py  # 告警基线
│   │   ├── alert_store.py      # 告警存储
│   │   ├── evtx_parser.py      # EVTX 解析器
│   │   ├── field_descriptions.py # 字段描述
│   │   ├── log_descriptions.py # 日志描述
│   │   ├── security_presets.py # 安全预设规则
│   │   ├── static_field_dict.py # 静态字段字典
│   │   └── windows_events_database.py # Windows 事件数据库
│   ├── models/                  # 数据模型
│   │   ├── event.py            # 事件模型
│   │   ├── log_file.py         # 日志文件模型
│   │   ├── pagination.py       # 分页模型
│   │   └── search_result.py    # 搜索结果模型
│   ├── utils/                   # 工具类
│   │   ├── memory_manager.py   # 内存管理
│   │   ├── progress_tracker.py # 进度追踪
│   │   └── xml_parser.py       # XML 解析
│   ├── main.py                  # 后端入口
│   └── __init__.py
├── frontend/                    # 编译后的前端资源
│   ├── assets/                 # 静态资源（JS、CSS、图片）
│   └── index.html              # 前端入口页面
├── cache/                       # SQLite 缓存目录
│   ├── alerts.db               # 告警数据库
│   └── *.cache.db              # 日志缓存数据库
├── logs/                        # 示例日志文件目录
│   ├── Security.evtx           # 安全日志
│   ├── System.evtx             # 系统日志
│   ├── Application.evtx        # 应用日志
│   └── ...                     # 其他日志文件
├── docs/                        # 文档目录
│   ├── API.md                  # API 文档
│   ├── ARCHITECTURE.md         # 架构文档
│   └── QUICKSTART.md           # 快速开始指南
├── main.py                      # 应用程序主入口
├── requirements.txt             # Python 依赖
├── LICENSE                      # 开源协议
└── VERSION                      # 版本号
```

<img width="1510" height="822" alt="image" src="https://github.com/user-attachments/assets/c44d416e-902e-4587-a73e-694890a3a97e" />


### 核心功能

#### 1. 智能日志解析
- **全格式支持**: Security、System、Application、PowerShell 等日志，后续版本将支持logs目录下的所有 Windows 事件日志
- **自动识别**: 基于 Channel 字段智能识别日志类型
- **深度解析**: 提取 100+ 字段，包括嵌套字段和键值对格式
- **高性能缓存**: SQLite 缓存机制，支持百万级事件加载
- **增量更新**: 智能缓存管理，避免重复解析
<img width="1613" height="1008" alt="image" src="https://github.com/user-attachments/assets/f8ecad15-f468-4f62-80ed-347103f8b343" />

#### 2. 全文搜索引擎
- **关键词搜索**: 支持全字段模糊匹配
- **高级搜索**: 多条件组合过滤（EventID、Level、Computer、时间范围等）
- **实时搜索**: 基于 SQLite FTS5 全文索引，秒级响应
- **搜索历史**: 自动保存搜索记录
- **结果高亮**: 关键词高亮显示

#### 3. 智能告警系统
- **内置规则库**: 
  - 57+ 条 Security 安全规则
  - 31+ 条 PowerShell 脚本规则
  - 31+ 条 System 系统规则
  - 15+ 条 Application 应用规则
- **自定义规则**: 
  - 匹配规则（单条件/多条件/逻辑组合）
  - 阈值规则（时间窗口 + 分组聚合）
  - 严重级别（Critical/High/Medium/Low/Info）
- **规则管理**:
  - JSON 格式导入导出
  - 规则启用/禁用
  - 规则编辑和删除
  - 批量操作
- **实时扫描**: 
  - 智能过滤，只返回匹配事件
  - 进度跟踪
  - 扫描历史记录

#### 4. AI 智能分析
<img width="1683" height="527" alt="image" src="https://github.com/user-attachments/assets/dabf4248-53d6-494e-b339-e70758ef2ac2" />

- **AI 对话助手**: 
  - 浮动 AI 面板，随时咨询
  - 流式输出，实时响应
  - 支持 OpenAI、Ollama、自定义 API
  - 支持一条或多条日志聚合分析
    
- **智能日志分析**:
  - 自动分析选中的日志事件
  - 识别安全威胁和异常行为
  - 提供修复建议和最佳实践
- **上下文工程**:
  - 知识库管理（添加/编辑/删除）
  - 自动从日志创建知识条目
  - 知识库启用/禁用控制
  - 上下文长度限制（避免 token 超限）
- **AI 配置**:
  - 支持多种 AI 模型（GPT-4、GPT-3.5、Claude 等）
  - 自定义 API 端点
  - Temperature 和 Max Tokens 调节
  - API Key 安全存储

#### 5. 可视化统计分析
- **登录分析**:
  - 成功/失败登录趋势图
  - Top IP 地址排行
  - Top 用户排行
  - 登录类型分布
  - 时间线分析（按小时/天/周）
- **进程监控**:
  - 进程创建趋势
  - 可疑进程检测
  - 进程命令行分析
  - 父子进程关系
- **账户管理**:
  - 用户创建/删除/修改统计
  - 组成员变更追踪
  - 权限提升检测
- **应用分析**:
  - 应用崩溃统计
  - 错误类型分布
  - 崩溃趋势分析
- **系统健康**:
  - 服务状态监控
  - 系统事件统计
  - 错误/警告分布

#### 6. 数据导出功能
- **CSV 导出**: 
  - 导出全部数据
  - 导出搜索结果
  - 导出高级搜索结果
  - 自定义字段选择
- **JSON 导出**: 完整事件数据导出
- **告警规则导出**: JSON 格式，方便团队共享

#### 7. 高级特性
- **字段元数据**: 100+ 字段的中文描述和说明
- **事件描述库**: 1000+ 事件 ID 的详细说明
- **内存管理**: 智能内存释放，支持大文件分析
- **进度追踪**: 实时显示解析/扫描进度
- **错误处理**: 完善的错误提示和恢复机制
- **列设置**: 自定义显示列，保存用户偏好

### 未来规划


#### 扩展支持（规划中）
- **所有 Windows 日志**: 支持所有 Windows 事件日志类型
- **Sysmon 日志**: 深度集成 Sysmon 高级监控

---

## 快速开始

### 环境要求

- **操作系统**: Windows 10/11 或 Windows Server 2016+
- **Python**: 3.8+ (开发环境需要)
- **内存**: 建议 4GB 以上
- **磁盘**: 至少 500MB 可用空间

### 安装方式

#### 方式一：直接下载可执行文件（推荐）

1. 访问 [Releases 页面](https://github.com/vam876/FastWinLog/releases/tag/v1.0.0)
2. 下载最新版本的 `FastWinLog-v1.0.0.exe`
3. 双击运行即可使用

#### 方式二：从源码运行

```bash
# 克隆仓库
git clone https://github.com/vam876/FastWinLog.git
cd FastWinLog

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

或者直接双击 `start.bat` 启动

### 基本使用

1. **加载日志文件**
   - 点击"选择文件"按钮
   - 选择 `.evtx` 格式的 Windows 事件日志文件
   - 等待解析完成（首次解析会创建缓存）

2. **搜索日志**
   - 使用顶部搜索框进行关键词搜索
   - 点击"高级搜索"进行多条件过滤
   - 支持按 EventID、Level、时间范围等筛选

3. **查看统计**
   - 切换到"统计"标签页
   - 查看登录分析、进程监控、账户管理等统计图表

4. **配置告警**
   - 切换到"告警"标签页
   - 启用内置规则或创建自定义规则
   - 点击"扫描"开始检测

5. **AI 分析**（可选）
   - 在设置中配置 AI API
   - 选中日志事件后点击 AI 按钮
   - 获取智能分析和建议

详细使用说明请参考 [快速开始指南](docs/QUICKSTART.md)

---

## 性能指标

- **解析速度**: 14,767 事件/秒（使用 pyevtx）
- **缓存机制**: SQLite 持久化，重启后秒开
- **内存优化**: 智能管理，最多保留 2 个文件在内存
- **搜索响应**: 基于 FTS5 全文索引，毫秒级响应
- **支持规模**: 单文件支持百万级事件

---

## AI 功能

### AI 对话助手

#### 1. 启用 AI 功能
```
设置 → AI 设置 → 配置 API
```

支持的 AI 服务：
- OpenAI (GPT-4, GPT-3.5-turbo)
- Azure OpenAI
- 自定义 API 端点（兼容 OpenAI 格式）

#### 2. 使用 AI 分析日志
```
选中日志事件 → 点击 AI 按钮 → 自动分析
```

AI 会自动：
- 识别事件类型和严重性
- 分析潜在的安全威胁
- 提供修复建议
- 关联相关事件

#### 3. 知识库管理
```
AI 面板 → 知识库图标 → 管理知识条目
```

功能：
- 添加自定义知识条目
- 从日志创建知识
- 启用/禁用知识库
- 控制上下文长度

### AI 配置示例

```json
{
  "provider": "openai",
  "apiKey": "sk-...",
  "model": "gpt-4",
  "temperature": 0.7,
  "maxTokens": 2000
}
```



---

## 开发指南

### 构建可执行文件

```bash
# 安装 PyInstaller
pip install pyinstaller

# 使用配置文件构建
pyinstaller build-windows.spec

# 生成的可执行文件位于 dist/ 目录
```

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/vam876/FastWinLog.git
cd FastWinLog

# 创建虚拟环境（推荐）
python -m venv venv
venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 运行开发服务器
python main.py
```

### 技术架构

- **前端**: React 18 + TypeScript + Vite
- **后端**: Python 3.12 + FastAPI 风格架构
- **解析引擎**: libevtx-python (pyevtx)
- **数据库**: SQLite (缓存) + 内存数据库
- **UI 容器**: pywebview

详细架构说明请参考 [架构文档](docs/ARCHITECTURE.md)

---

## 文档

- [安装指南](INSTALL.md) - 详细的安装步骤和环境配置
- [快速开始](docs/QUICKSTART.md) - 快速上手指南
- [API 文档](docs/API.md) - 后端 API 接口说明
- [架构文档](docs/ARCHITECTURE.md) - 系统架构和设计说明

---

## 贡献指南

欢迎贡献代码、报告问题或提出建议！

### 如何贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

### 报告问题

如果发现 Bug 或有功能建议，请在 [Issues](https://github.com/vam876/FastWinLog/issues) 页面提交。

---

## 许可证

本项目采用 **Apache License 2.0** 开源协议 - 详见 [LICENSE](LICENSE) 文件。

---

## 致谢

- [pywebview](https://pywebview.flowrl.com/) - 提供桌面应用容器
- [libevtx](https://github.com/libyal/libevtx) - 高性能 EVTX 解析库
- [React](https://reactjs.org/) - 前端 UI 框架
- 所有贡献者和使用者

---

## 联系方式

- **项目主页**: [https://github.com/vam876/FastWinLog](https://github.com/vam876/FastWinLog)
- **问题反馈**: [GitHub Issues](https://github.com/vam876/FastWinLog/issues)
- **相关项目**: 
  - [FastWLAT - Web 日志分析工具](https://github.com/vam876/FastWLAT)
  - [FastLinLog - Linux 日志分析工具](https://github.com/vam876/FastLinLog)

---

<div align="center">

**如果这个项目对你有帮助，请给个 Star！**

Made with ❤️ by FastWinLog Team

</div>

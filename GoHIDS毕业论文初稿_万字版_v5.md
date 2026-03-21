# 基于 GoHIDS 的主机入侵检测与联动取证平台设计与实现

## 摘要

随着数字化转型的深入推进，终端主机数量不断增长，业务系统在开放网络环境中的暴露面显著扩大。传统“边界防护为主、终端防护为辅”的安全建设方式，在面对横向移动、无文件攻击、弱口令滥用、异常外联等复杂威胁时，往往存在发现滞后、定位困难、处置链路断裂等问题。针对上述痛点，本文围绕一个可部署、可演示、可扩展的主机安全平台开展研究与实现，设计并完成了 GoHIDS 主机入侵检测与联动取证系统。

系统采用 Agent/Server/Web 三层架构：Agent 侧基于多采集器机制完成主机运行态数据采集，包括进程、网络连接、文件变更、注册表变更、安全日志、USB 事件、性能指标和资产基线；Server 侧基于 gRPC 双向流接收主机数据并下发任务，基于 Gin 构建管理 API，基于 GORM+MySQL 完成结构化持久化；Web 侧基于 Vue3、Element Plus 和 ECharts 实现态势总览、主机画像、事件时间线与告警处置界面。系统在检测闭环上实现了“规则匹配 + 威胁情报 + 自动取证”联动机制：当检测到异常外联或规则命中后，服务端可自动下发取证任务，Agent 回传进程路径、命令行、父子进程关系、连接信息与样本 SHA-256 哈希，提高告警可解释性与可处置性。

本文从需求分析、架构设计、数据库设计、模块实现、测试验证五个维度展开。实践表明，系统能够在单机与小规模主机组场景中稳定运行，实现主机数据统一采集、风险识别、告警可视化和证据联动回传，具备较强工程可行性。最后，本文结合实现过程提出系统在规则语义增强、规模化部署、跨平台一致性和自动化测试方面的改进方向。

**关键词**：主机入侵检测；安全运营；gRPC 双向流；威胁情报；自动取证；资产基线

---

## Abstract

As enterprise digitalization accelerates, endpoint hosts are expanding rapidly and attack surfaces are becoming broader. Traditional perimeter-centric defense often fails to detect host-level threats in time, especially under lateral movement, credential abuse, and suspicious outbound connections. To address these issues, this thesis designs and implements GoHIDS, a practical host intrusion detection and forensic linkage platform.

The platform adopts a three-layer architecture: Agent, Server, and Web. The Agent collects host telemetry through modular collectors, including process, network, file, registry, security log, USB, performance, and baseline data. The Server uses bidirectional gRPC streaming for real-time telemetry ingestion and command dispatch, Gin for REST APIs, and GORM+MySQL for persistence. The Web console is built with Vue3, Element Plus, and ECharts for dashboard visualization, host profiling, timeline analysis, and alert handling.

GoHIDS implements a closed-loop mechanism of “rule matching + threat intelligence + automated forensics”. Once suspicious behavior is detected, the server can trigger forensic tasks on target hosts, and collect process path, command line, parent-child relation, connection details, and SHA-256 file hash to enrich incident context and support response decisions.

This thesis presents requirement analysis, architecture design, database design, key implementation details, and test validation. Experimental results show that GoHIDS can stably support unified host telemetry collection, risk detection, visualized alerting, and evidence linkage in single-node and small-scale scenarios. Future work includes richer rule semantics, scalable deployment, better cross-platform consistency, and automated test pipelines.

**Keywords**: Host-based intrusion detection, Security operations, Bidirectional gRPC streaming, Threat intelligence, Automated forensics, Baseline drift detection

---

## 第1章 绪论

### 1.1 研究背景

在云化、移动化与远程办公常态化背景下，主机端成为网络攻击最常见的落点之一。攻击者常通过弱口令、恶意脚本、漏洞利用、钓鱼载荷等方式获得初始权限，随后执行持久化、横向移动与数据外传。此类攻击过程中，许多关键痕迹并不一定体现在边界设备日志中，而更多存在于主机本地行为层，包括：

这些痕迹通常表现为异常进程启动、父子进程链条不合理、敏感目录被高频改写、注册表关键项被篡改、主机突然外联可疑地址以及短时间登录失败次数激增等现象。仅依赖边界设备很难完整还原此类主机侧行为，因此以主机为中心建设检测与响应能力具有明确的现实意义。主机入侵检测并不是替代边界防护，而是在现有体系上补齐“最后一公里”的可见性，使告警追溯与事件处置具备更可靠的证据基础。

### 1.2 研究目的与意义

本课题的核心目标不是追求抽象层面的“理论最优”，而是完成一个可落地、可运行、可演示的安全闭环平台，让主机行为数据能够持续采集、实时汇聚、规则分析并可视展示，同时在高风险场景下自动触发取证动作。换言之，系统希望把告警从“只提示异常”推进到“能解释异常”，把处置从“完全人工排查”推进到“具备自动化联动能力”，并最终把分散在不同工具中的数据整合到统一视图中。该研究一方面覆盖了后端服务、前端交互、协议通信、数据库设计和安全逻辑实现等完整的软件工程要素，具有较强实践训练价值；另一方面也能为中小规模内网提供一套成本可控、便于持续迭代的主机安全监测方案。

### 1.3 国内外研究现状

国际研究方面，Denning 提出的入侵检测模型奠定了异常检测理论基础；Forrest 等提出的主机行为序列思路推动了主机侧检测发展。工程领域中，Snort 与 Suricata 形成了规则检测生态，Wazuh、OSSEC 等系统在主机审计与 SIEM 联动方面积累了实践。

国内研究方面，近年围绕网络安全态势感知、入侵检测算法融合、数据库入侵检测、工控安全检测等方向形成了大量研究成果。相关文献普遍强调：仅有告警不足以支撑实战，检测系统需具备资产视角、行为上下文与响应能力。本文系统设计与实现正是沿此思路展开，重点放在“工程闭环”和“可解释检测”上。

### 1.4 研究内容

围绕 GoHIDS 系统，本文完成了从架构到落地的完整实现工作。首先设计了 Agent、Server 与 Web 三层协同架构及其通信协议，在此基础上实现主机多源采集器机制和统一数据上报模型；随后在服务端完成事件解析、缓存管理、告警生成与数据库持久化流程，并进一步接入威胁情报联动与自动取证任务下发机制；最后在 Web 端实现态势总览、主机详情和告警导出等功能，并结合测试方案对系统可用性进行了验证。

### 1.5 论文结构

1. 第1章：绪论。  
2. 第2章：相关技术与理论基础。  
3. 第3章：需求分析与可行性分析。  
4. 第4章：系统总体设计（含流程图、数据库图）。  
5. 第5章：系统详细设计与关键实现。  
6. 第6章：系统测试与结果分析。  
7. 第7章：总结与展望。  

---

## 第2章 相关技术与理论基础

### 2.1 主机入侵检测技术基础

主机入侵检测系统通过持续观测主机内部行为来识别异常风险。与网络侧检测相比，主机侧最大的优势在于语义信息更完整，能够直接获取进程、用户、文件和日志等关键实体；但同时也面临数据类型繁杂、噪声较多以及跨平台差异明显的问题。在工程实践中，单一方法往往难以兼顾准确率与可解释性。仅依赖规则匹配虽然实现简单，但对未知行为覆盖有限；仅依赖统计异常虽有发现未知威胁的潜力，却容易引入误报。基于这一现实，本文采用“规则匹配、行为事件分析与情报联动”相结合的思路，在保证系统可实现性的前提下提升检测有效性。

### 2.2 gRPC 与 Protocol Buffers

在主机入侵检测系统中，采集端需要以较高频率持续上报进程、网络连接与日志事件，通信机制的效率直接影响平台的实时监测能力。传统基于 HTTP/1.1 的轮询方式通常采用“客户端定时发起请求—服务端返回数据”的交互模式，其本质是离散式、短连接或半长连接通信。该模式在持续上报场景下会产生明显瓶颈：一方面，频繁的请求建立与释放会带来重复的 TCP 握手、HTTP 报文头传输和上下文切换开销，随着主机数量增加，服务端线程与连接管理压力显著上升；另一方面，轮询周期决定了数据可见性的下限，周期过短会放大网络与计算负担，周期过长又会导致告警滞后，难以满足安全事件“准实时发现”的需求。此外，HTTP/1.1 在同一连接上的并发复用能力有限，服务端主动下发控制指令也往往需要额外设计反向通道，系统复杂度较高。

相比之下，gRPC 构建于 HTTP/2 之上，利用二进制分帧与多路复用机制，在单条长连接中并行承载多个流式消息，能够有效降低连接管理成本并提升链路利用率。其双向流模式允许客户端持续推送监测数据的同时，服务端在同一通道内异步下发控制命令，天然契合“数据上报+任务调度”一体化需求。Protocol Buffers 作为 gRPC 默认序列化协议，通过预定义消息结构与字段编号实现紧凑编码，采用 Varint 等机制对整数进行可变长压缩，避免了文本协议在字段名、分隔符与冗余字符上的额外开销，在带宽占用、反序列化速度与跨语言一致性方面均优于 JSON 等文本格式。基于上述机制，gRPC 与 ProtoBuf 在高频、小包、长时通信场景下能够同时保障传输效率、实时性与可扩展性，因此本系统选择 gRPC 作为主机与服务端之间的核心通信方案。

### 2.3 服务端框架与数据层技术

服务端框架选型遵循“稳定、易维护、与项目规模匹配”的原则。Gin 用于构建 Web API，其路由机制清晰、性能表现稳定，能够满足中小规模安全平台的接口需求。GORM 负责对象关系映射与数据访问，减少了大量样板 SQL 代码，同时便于后续模型演进。MySQL 作为关系型存储承载告警、事件、资产和用户等核心结构化数据，在事务一致性和查询能力方面能够满足本课题的实现要求。  

### 2.4 前端技术栈

前端采用 Vue3 + TypeScript 开发，Element Plus 提供中后台组件，ECharts 负责数据可视化。该组合在工程上可快速搭建操作界面，并满足仪表盘、趋势图和列表筛查等常见安全运营视图需求。

### 2.5 安全机制与响应框架

在安全机制方面，系统采用 JWT 作为接口鉴权手段，用户登录成功后由服务端签发令牌并在后续请求中校验。密码存储使用 bcrypt 进行哈希处理，降低明文泄露风险。针对外联风险识别，系统接入 ThreatBook 情报查询能力，对公网 IP 做恶意性研判。为了打通检测与处置链路，服务端还可通过 gRPC 反向下发取证任务，使系统从“发现问题”进一步走向“辅助处置”。  

---

## 第3章 需求分析与可行性分析

### 3.1 业务需求分析

从安全运营实践看，系统建设首先要解决数据分散问题，即把不同主机、不同类型的行为数据统一采集并归一化，避免“多工具并存但互不联动”的局面。在此基础上，系统还要具备对关键异常的及时发现能力，尤其是可疑进程、恶意外联和异常登录等高风险行为。更重要的是，告警不能只停留在“触发”层面，而应携带进程路径、命令行和主机身份等上下文信息，便于人员快速判断。最后，系统需要提供可执行的处置入口和可视化查询能力，使总览、详情、时间线和导出形成完整操作闭环。

### 3.2 功能需求分析

#### 3.2.1 Agent 侧功能需求

Agent 侧需要承担主机本地数据采集与上报职责。系统要求其能够持续发送心跳和主机基础信息，并对进程、网络、文件、注册表、安全日志、USB 以及性能数据进行周期采集。除常规监测外，Agent 还应具备资产快照与基线差异检测能力，用于识别主机关键状态变化。考虑到联动处置场景，Agent 必须支持接收并执行服务端下发的取证任务。同时，为保证长期运行稳定性，通信层还需具备断线重连与持续发送能力。

#### 3.2.2 Server 侧功能需求

Server 侧是系统的数据汇聚与业务处理中心，需要接收并解析来自不同主机的多类型上报数据，并维护主机在线状态及内存缓存视图。对于可持久化的信息，服务端应完成事件、告警和资产数据入库，以支持查询与审计。结合检测逻辑，服务端还需负责风险识别与告警生成，并支持 ThreatBook 情报联动开关控制。在响应环节，服务端应能够向指定 Agent 下发取证命令。为了支撑前端功能，服务端还要提供覆盖 Dashboard、主机详情、告警查询、资产查询与数据导出的 API 接口。

#### 3.2.3 Web 侧功能需求

Web 侧主要面向安全管理员的日常使用场景。系统应支持登录认证与会话管理，保证访问过程可控。首页需要提供态势总览能力，直观展示在线主机规模、告警趋势和系统分布情况。主机详情页应能够下钻到进程、连接、端口、用户、注册表和资产变更记录等细粒度数据。针对事件复盘需求，前端还应支持告警列表查询与导出，并提供威胁情报开关控制入口，以便根据环境策略进行动态调整。

### 3.3 非功能需求分析

除功能实现外，系统还需要满足若干非功能指标。实时性方面，关键监测数据应在秒级到分钟级范围内可见，避免告警延迟过大。可维护性方面，各模块职责边界应保持清晰，便于后续新增采集器与接口。可扩展性方面，系统应预留接入更多规则、更多主机节点及更复杂存储策略的能力。可靠性方面，当通信链路中断或服务重启时，系统需能够恢复运行状态并保持主机信息连续性。安全性方面，认证鉴权、密码加密存储和接口权限隔离必须作为基础要求落实到实现中。

### 3.4 可行性分析

#### 3.4.1 技术可行性

Go、gRPC、Gin、GORM、Vue3 等技术均具备成熟生态和大量工程实践，适合毕业设计周期内实现可运行系统。项目现有代码已覆盖从采集到展示的全链路，技术可行性高。

#### 3.4.2 经济可行性

系统核心组件均为开源技术，部署可在普通开发机完成，成本可控。

#### 3.4.3 实施可行性

当前代码目录结构清晰，前后端分离，便于持续迭代与演示部署。可在课程答辩场景快速复现实验。

### 3.5 用例分析

```mermaid
flowchart LR
  A[安全管理员] --> B[登录系统]
  A --> C[查看态势总览]
  A --> D[查看主机详情]
  A --> E[查询告警]
  A --> F[导出事件/告警]
  A --> G[切换威胁情报开关]
  H[Agent程序] --> I[上报监测数据]
  I --> J[服务端分析与入库]
  J --> K[生成告警]
  K --> A
  J --> L[下发取证任务]
  L --> H
```

---

## 第4章 系统总体设计

### 4.1 总体架构设计

GoHIDS 采用典型三层架构。Agent 层部署在被监控主机侧，靠近数据源，负责采集与初步结构化处理；Server 层承担数据汇聚、检测分析、告警联动、持久化和接口服务职责；Web 层面向运维与安全人员，提供可视化展示、检索分析和交互操作能力。该分层方式使采集、分析和展示解耦，便于后续扩展与维护。

```mermaid
flowchart TB
  subgraph Host["被监控主机"]
    A1[Heartbeat Collector]
    A2[Process Collector]
    A3[Network Collector]
    A4[File/Registry/SecurityLog Collector]
    A5[Baseline/Forensic Collector]
    AM[Collector Manager]
    A1 --> AM
    A2 --> AM
    A3 --> AM
    A4 --> AM
    A5 --> AM
  end

  subgraph Server["GoHIDS Server"]
    S1[gRPC Transfer Server]
    S2[Agent Service]
    S3[Rule/Threat Intelligence Linkage]
    S4[Repository(GORM)]
    S5[HTTP API(Gin)]
  end

  subgraph DB["MySQL"]
    D1[(Agent)]
    D2[(SecurityEvent)]
    D3[(Alert)]
    D4[(Process/Network/FileEvent)]
    D5[(Asset Tables)]
    D6[(User)]
  end

  subgraph Web["Vue3 Web Console"]
    W1[Dashboard]
    W2[Agents]
    W3[Alerts]
    W4[Timeline/Asset Views]
  end

  AM -- "gRPC Stream RawData" --> S1
  S1 --> S2
  S2 --> S3
  S2 --> S4
  S4 --> D1
  S4 --> D2
  S4 --> D3
  S4 --> D4
  S4 --> D5
  S4 --> D6
  S5 --> S2
  W1 --> S5
  W2 --> S5
  W3 --> S5
  W4 --> S5
  S2 -- "gRPC Command(Forensics)" --> AM
```

### 4.2 系统工作流程设计

#### 4.2.1 常规监测流程

```mermaid
sequenceDiagram
  participant Agent
  participant gRPC as gRPC Server
  participant Service as AgentService
  participant Repo as Repository
  participant DB as MySQL
  participant Web as Web UI

  Agent->>gRPC: 持续发送 RawData
  gRPC->>Service: ProcessData(agentID, data)
  Service->>Repo: UpsertAgent / CreateEvent
  Repo->>DB: 写入 Agent, Event, Alert, Asset
  Web->>Service: HTTP 查询(仪表盘/主机/告警)
  Service-->>Web: 返回结构化数据
```

#### 4.2.2 恶意外联联动取证流程

```mermaid
sequenceDiagram
  participant Agent
  participant Service as AgentService
  participant TI as ThreatBook
  participant DB as MySQL

  Agent->>Service: 上报 Network CONNECT 事件
  Service->>Service: 过滤公网IP并构建上下文
  Service->>TI: QueryIPs(ip[])
  TI-->>Service: 恶意性判定结果
  Service->>DB: 写入 SecurityEvent + Alert
  Service-->>Agent: 下发 Forensics Command
  Agent->>Agent: 执行取证(进程/哈希/连接)
  Agent->>Service: 回传 Forensics Report
  Service->>DB: 写入取证报告事件
```

### 4.3 软件工程分层设计

系统分层遵循“采集层-传输层-服务层-数据层-展示层”：

1. 采集层：`internal/agent/collector`；
2. 传输层：`internal/agent/transport` 与 `internal/server/grpc`；
3. 服务层：`internal/server/service`；
4. 数据层：`internal/server/model`、`internal/server/repository`；
5. 展示层：`web/src/views`、`web/src/components`。

该分层有利于解耦与职责隔离，符合软件工程可维护性要求。

### 4.4 MySQL 数据库设计

#### 4.4.1 数据库 E-R 图（核心）

```mermaid
erDiagram
  AGENT ||--o{ PERFORMANCE_LOG : has
  AGENT ||--o{ SECURITY_EVENT : has
  AGENT ||--o{ ALERT : has
  AGENT ||--o{ PROCESS_EVENT : has
  AGENT ||--o{ NETWORK_EVENT : has
  AGENT ||--o{ FILE_EVENT : has
  AGENT ||--o{ ASSET_PORT : has
  AGENT ||--o{ ASSET_USER : has
  AGENT ||--o{ ASSET_CHANGE : has

  USER {
    bigint id PK
    varchar username
    varchar password_hash
    varchar role
    datetime created_at
    datetime last_login
  }

  AGENT {
    varchar id PK
    varchar hostname
    varchar product
    varchar version
    text intranet_ipv4
    datetime last_seen
    varchar status
  }

  ALERT {
    bigint id PK
    varchar agent_id FK
    datetime timestamp
    varchar type
    text message
    varchar severity
    varchar status
  }

  SECURITY_EVENT {
    bigint id PK
    varchar agent_id FK
    datetime timestamp
    varchar event_type
    text details
    varchar severity
  }

  PROCESS_EVENT {
    bigint id PK
    varchar agent_id FK
    datetime timestamp
    varchar action
    int pid
    int ppid
    varchar name
    text path
    text cmdline
    varchar user
  }
```

#### 4.4.2 数据库关系结构图（逻辑）

```mermaid
flowchart LR
  A[agent] --> B[process_event]
  A --> C[network_event]
  A --> D[file_event]
  A --> E[security_event]
  A --> F[alert]
  A --> G[asset_port]
  A --> H[asset_user]
  A --> I[asset_change]
  A --> J[performance_log]
  U[user] --> K[login/jwt]
```

#### 4.4.3 关键表设计说明

1. `agent`：主机主表，记录在线状态与基础属性。  
2. `security_event`：统一安全事件流水，便于留痕与分析。  
3. `alert`：高层告警表，用于界面展示与运营处理。  
4. `process_event/network_event/file_event`：行为时间线。  
5. `asset_port/asset_user/asset_change`：资产快照与漂移检测。  
6. `user`：登录账号与权限角色。  

#### 4.4.4 数据库物理结构设计表

表 4.1 主机信息表（`agent`）用于存储被监控主机的基础属性与在线状态，是系统进行主机身份识别、资产展示和在线性判断的核心主数据表，并作为行为事件关联的主键来源。

| 序号 | 字段名（列名） | 数据类型 | 长度 | 主外键标识 | 是否允许为空 | 字段说明（中文备注） |
|---|---|---|---|---|---|---|
| 1 | id | varchar | 64 | PK | 否 | 主机唯一标识（AgentID） |
| 2 | hostname | varchar | 128 | - | 否 | 主机名 |
| 3 | product | varchar | 128 | - | 是 | 操作系统/产品信息 |
| 4 | version | varchar | 32 | - | 是 | Agent 版本号 |
| 5 | intranet_ipv4 | varchar | 512 | - | 是 | 内网 IPv4 列表（逗号分隔） |
| 6 | last_seen | datetime | - | - | 否 | 最近心跳/上报时间 |
| 7 | status | varchar | 16 | - | 否 | 主机状态（online/offline） |

表 4.2 安全事件表（`security_event`）用于统一存储主机侧产生的安全审计事件，覆盖登录异常、文件变更、注册表变更、入侵检测命中与取证报告等，支撑告警回溯与审计分析。

| 序号 | 字段名（列名） | 数据类型 | 长度 | 主外键标识 | 是否允许为空 | 字段说明（中文备注） |
|---|---|---|---|---|---|---|
| 1 | id | bigint | 20 | PK | 否 | 安全事件主键，自增 |
| 2 | agent_id | varchar | 64 | FK(`agent.id`) | 否 | 事件所属主机 ID |
| 3 | timestamp | datetime | - | - | 否 | 事件发生时间 |
| 4 | event_type | varchar | 64 | - | 否 | 事件类型（如 LOGIN_FAILED） |
| 5 | details | text | - | - | 否 | 事件详情（JSON 字符串） |
| 6 | severity | varchar | 16 | - | 否 | 严重等级（INFO/WARN/HIGH/CRITICAL） |

表 4.3 进程事件表（`process_event`）用于记录主机进程生命周期变化及关键上下文，支持进程时间线分析、可疑进程定位和告警证据补全，是行为检测与溯源分析的重要数据基础。

| 序号 | 字段名（列名） | 数据类型 | 长度 | 主外键标识 | 是否允许为空 | 字段说明（中文备注） |
|---|---|---|---|---|---|---|
| 1 | id | bigint | 20 | PK | 否 | 进程事件主键，自增 |
| 2 | agent_id | varchar | 64 | FK(`agent.id`) | 否 | 所属主机 ID |
| 3 | timestamp | datetime | - | - | 否 | 事件时间 |
| 4 | action | varchar | 16 | - | 否 | 事件动作（START/EXIT/SNAPSHOT） |
| 5 | pid | int | 11 | - | 否 | 进程 ID |
| 6 | ppid | int | 11 | - | 是 | 父进程 ID |
| 7 | name | varchar | 128 | - | 否 | 进程名称 |
| 8 | cmdline | text | - | - | 是 | 进程命令行参数 |
| 9 | path | varchar | 512 | - | 是 | 可执行文件路径 |
| 10 | user | varchar | 64 | - | 是 | 进程所属用户 |
| 11 | checksum | varchar | 128 | - | 是 | 文件摘要值（如 SHA-256） |

### 4.5 接口设计

#### 4.5.1 公共接口

1. `POST /api/login`：登录并返回 token。  

#### 4.5.2 鉴权接口（部分）

1. `GET /api/dashboard/stats`：仪表盘统计；  
2. `GET /api/agents`、`GET /api/agent/:id`：主机信息；  
3. `GET /api/alerts`：告警列表；  
4. `GET /api/events/process|network|file`：时间线查询；  
5. `GET /api/assets/ports|users|changes`：资产查询；  
6. `GET /api/export/events|alerts`：数据导出；  
7. `GET/POST /api/config/threatbook`：情报开关配置。  

---

## 第5章 系统详细设计与实现

### 5.1 Agent 端关键实现

#### 5.1.1 Collector 管理机制

`collector.Manager` 通过统一注册和启动机制管理多个采集器。各采集器实现统一接口：

1. `Name()`：采集器名称；
2. `Start(ch)`：启动采集并向通道写入 `RawData`；
3. `Stop()`：停止采集。

该设计具备良好扩展性：新增采集器仅需实现接口并在 `cmd/agent/main.go` 注册。

#### 5.1.2 进程采集与规则检测实现

本系统在 `internal/agent/collector/process.go` 中实现了面向主机运行态的进程采集逻辑，整体思路是以固定周期执行全量枚举，再通过快照差分提取增量事件。采集线程启动后首先进行短暂延时，避免与其他采集器同时抢占系统资源，随后以定时器驱动周期任务。每次周期到达时，程序调用 gopsutil 的进程查询接口获取当前系统进程集合，并逐个读取进程名称、进程路径、命令行、父进程标识、创建用户等属性，将其组织为以内核 PID 为键的进程映射。该映射不仅承担了当次上报数据的组织功能，也作为后续状态对比的输入，构成“当前快照”。

为了捕捉进程生命周期变化，代码维护了一个“上一轮快照”缓存。当新快照构建完成后，系统首先遍历当前映射并检查每个 PID 是否在历史映射中存在。若不存在，则判定该进程在两个采集窗口之间新启动，生成 `START` 事件并附带完整上下文。随后系统再反向遍历历史映射，检查哪些 PID 未出现在当前映射中，将其判定为已退出进程并生成 `EXIT` 事件。由于该策略以稳定的 PID 集合作为对比基准，能够在无需内核驱动的前提下有效还原大多数常规进程的启动与退出行为，既满足了工程可实现性，也保证了事件语义的清晰性。

在规则检测环节，系统并非对全部进程重复扫描，而是仅对新出现的 `START` 事件执行规则匹配。这样做的原因在于，安全风险往往首先体现在“新进程启动行为”上，对同一进程进行高频重复匹配会显著增加计算开销且收益有限。规则引擎会将进程命令行与规则内容字段进行匹配，并结合元数据对路径与用户进行约束校验。命中后系统立即构造入侵检测数据并上报，数据中保留规则 SID、规则消息、进程路径、命令行以及父进程信息，服务端可据此在告警界面展示更完整的溯源上下文。该设计避免了传统黑盒告警“只报异常、不报原因”的问题，提升了安全运营人员的研判效率。

考虑到进程枚举属于高频系统调用，若策略不当容易造成额外 CPU 占用，系统在实现中加入了多项性能控制措施。最核心的手段是限制采集频率，将默认周期设置为 10 秒，从机制上避免无意义的亚秒级轮询。其次，代码采用快照缓存与差分上报策略，不对全量进程反复发送重复数据，而是仅输出状态变化事件，从而降低序列化与网络传输压力。再次，规则匹配限定在新增进程路径上执行，避免对稳定运行进程反复做字符串匹配计算。采集流程还对单个进程信息读取失败采取容错跳过策略，避免异常阻塞整个采集循环。综合来看，这一实现在检测覆盖率与资源开销之间取得了较好的工程平衡，使系统能够在持续运行场景下保持可接受的性能表现。

#### 5.1.3 网络连接采集实现

在 `network.go` 中，采集器周期扫描连接并识别连接建立和断开事件。与常规连接采集不同，本系统补全进程上下文（`process_name`、`process_path`、`cmdline`），服务端可据此判断“哪个进程连接了哪个 IP”，为恶意外联处置提供直接证据。

#### 5.1.4 安全日志与系统事件采集

Windows 平台下，`security_log.go` 通过 PowerShell 调用 `Get-WinEvent` 获取 4624/4625/4688 等事件，提取登录与进程创建关键信息。服务端根据 Event ID 与 LogonType 生成不同级别告警，实现对暴力尝试与远程登录行为的监控。

#### 5.1.5 资产基线设计与差异检测

`baseline.go` 负责主机基础资产快照与差异识别：

1. 首次运行生成 `baseline.json`；  
2. 周期采集并与历史基线比较；  
3. 识别主机名、系统版本、IP、端口变化；  
4. 生成 `DataTypeAssetChange` 与 `DataTypeAssetSnapshot` 数据。  

该策略将“单次数据采集”升级为“持续资产漂移监控”，具备运维与安全双重价值。

#### 5.1.6 自动取证执行实现

`forensic.go` 监听服务端下发任务，执行取证动作：

1. 根据目标 IP 在当前连接中定位目标 PID；  
2. 获取进程名、路径、命令行、父进程信息；  
3. 计算样本文件 SHA-256；  
4. 生成结构化报告回传服务端。  

该模块是系统“检测-响应”闭环的关键执行点。

### 5.2 Server 端关键实现

#### 5.2.1 gRPC 双向流服务

`internal/server/grpc/server.go` 在接收首包后注册 Agent 流，实现服务端主动向指定 Agent 发送命令。服务端长期监听流式数据并调用 `ProcessData` 处理，实现实时上报。

#### 5.2.2 服务层数据处理总线

`internal/server/service/service.go` 是核心业务层。处理逻辑包括：

1. 更新内存缓存与主机在线时间；  
2. Upsert 主机基础信息；  
3. 根据 DataType 分发到不同处理函数；  
4. 维护进程、连接、服务等前端展示数据；  
5. 写入事件表和告警表。  

分发模型可表示为：

```mermaid
flowchart TB
  A[ProcessData] --> B{DataType}
  B -->|Process| C[handleProcess]
  B -->|Network| D[handleNetwork]
  B -->|File| E[handleFile]
  B -->|Registry| F[handleRegistry]
  B -->|SecurityLog| G[handleSecurityLog]
  B -->|AssetPort/User/Change| H[handleAsset*]
  B -->|Forensics| I[handleForensics]
```

#### 5.2.3 告警生成与等级策略

系统告警来自三类来源：

1. 规则匹配类告警：进程命中规则；  
2. 安全日志类告警：登录失败/远程登录等行为；  
3. 情报联动类告警：外联恶意 IP。  

告警级别分为 `INFO/WARN/HIGH/CRITICAL`，并在前端以颜色标签区分，便于运营人员快速筛查。

#### 5.2.4 威胁情报联动机制

在网络事件处理中，服务端提取公网目标 IP 批量查询 ThreatBook。若判定恶意，则：

1. 写入高危 `SecurityEvent` 与 `Alert`；  
2. 组装含进程上下文的描述信息；  
3. 向对应 Agent 下发取证命令。  

该机制提升了误报过滤能力，并让告警更接近“可执行动作”。

#### 5.2.5 API 与鉴权实现

系统在启动时初始化 JWT 密钥与有效期，`/api/login` 验证用户后签发 token，受保护路由通过中间件校验 Authorization 头。该机制满足毕业项目所需基础安全要求。

### 5.3 Web 前端实现

#### 5.3.1 登录与请求拦截

前端在 `web/src/api/index.ts` 统一封装 axios，自动注入 token。后端返回 401 时前端清理 token 并跳转登录页。

#### 5.3.2 Dashboard 设计

`Home.vue` 展示在线/离线主机数、告警总量、告警趋势、系统分布和 Top 进程，同时提供 ThreatBook 开关。运营人员可在单页完成总体态势感知。

#### 5.3.3 主机详情设计

`Agents.vue` 将主机详情划分为多标签页：

1. 资产变更时间线；
2. 进程监控视图；
3. 网络连接视图；
4. 监听端口、系统用户、服务列表；
5. 注册表监控视图。

这种分区布局兼顾“概览”和“深挖”，符合安全研判工作流。

#### 5.3.4 告警管理设计

`Alerts.vue` 展示告警级别、类型、消息与时间，支持导出事件与告警数据，便于离线分析或审计留档。

### 5.4 关键工程特性总结

1. 模块化采集：便于扩展新采集源；  
2. 单通道双向流：降低通信复杂度；  
3. 事件与资产并行建模：兼顾时间线和当前态势；  
4. 情报与取证联动：提升告警处置价值；  
5. 前后端解耦：便于独立演进。  

---

## 第6章 系统测试与结果分析

### 6.1 测试目标

验证系统是否满足“可采集、可分析、可告警、可联动、可展示”的核心目标。

### 6.2 测试环境

1. 操作系统：Windows（Agent）+ Windows/Linux（Server）；  
2. 运行环境：Go 1.2x、Node.js、MySQL 8.x；  
3. 端口规划：gRPC `:8888`，HTTP `:8080`。  

### 6.3 测试方法

采用黑盒功能测试与白盒链路验证结合方式：

1. 接口测试：验证返回结构、鉴权、错误处理；
2. 场景测试：模拟主机行为变化，观察告警与前端展示；
3. 链路测试：验证取证命令下发与结果回传。

### 6.4 测试用例设计

#### 6.4.1 登录鉴权测试

1. 正确账号密码登录，返回 token；  
2. 错误密码登录，返回认证失败；  
3. 无 token 访问受保护接口，返回未授权。  

#### 6.4.2 主机在线状态测试

1. 启动 Agent 后，主机列表出现对应主机；  
2. 停止 Agent 超过阈值后，前端显示离线。  

#### 6.4.3 进程事件测试

1. 手动启动进程，验证出现 `START` 事件；  
2. 关闭进程，验证出现 `EXIT` 事件；  
3. 命中规则关键字时，验证产生入侵告警。  

#### 6.4.4 网络事件与情报联动测试

1. 创建外联连接，验证连接事件写入；  
2. 命中恶意 IP（测试样本）时，验证告警生成；  
3. 验证取证任务自动下发和回传。  

#### 6.4.5 基线漂移测试

1. 新开监听端口，验证资产变更 `ADD`；  
2. 关闭监听端口，验证资产变更 `DELETE`；  
3. 网络地址变化时，验证 IP 变更记录。  

#### 6.4.6 告警导出测试

1. 点击导出事件，下载 JSON；  
2. 点击导出告警，下载 JSON；  
3. 检查内容完整性与时间排序。  

### 6.5 测试结果分析

1. **功能正确性**：主链路功能可用，满足既定需求。  
2. **链路完整性**：从采集、入库、可视化到取证回传形成闭环。  
3. **实时性表现**：在 10 秒采集周期下，前端具备可接受的准实时显示能力。  
4. **稳定性表现**：连接异常后可重连，服务重启后可恢复主机基础状态。  

### 6.6 存在问题

1. 规则引擎当前以关键字匹配为主，复杂攻击语义覆盖有限；  
2. 尚未建立完整性能压测与容量评估报告；  
3. Windows/ Linux 采集字段在部分场景存在差异；  
4. 前端尚未提供细粒度告警处置流（如工单状态机）。  

### 6.7 优化建议

1. 引入规则优先级和去重策略，降低告警噪声；  
2. 引入消息队列削峰，提升高并发写入稳定性；  
3. 对关键 API 增加限流与审计日志；  
4. 建立自动化测试流水线和回归基线。  

---

## 第7章 总结与展望

本文围绕 GoHIDS 主机入侵检测系统完成了从需求到实现、从设计到测试的完整软件工程实践。系统在架构层面采用 Agent/Server/Web 分层，在能力层面实现了多源主机采集、双向流式传输、规则与情报联动、自动取证回传、可视化运营展示，满足“能发现、能解释、能联动”的核心目标。与单点检测方案相比，本系统在工程完整性和处置可执行性方面具有明显优势。

在毕业设计维度，本项目覆盖了后端服务、协议通信、数据库建模、前端可视化与安全业务逻辑，形成了完整可演示成果。系统当前仍处于教学与研究型阶段，未来可继续向生产级能力演进：

1. 检测能力升级：引入多事件关联分析、统计异常模型和更细粒度规则语义；  
2. 架构能力升级：引入异步队列、分布式存储与多实例调度；  
3. 运维能力升级：完善配置中心、灰度发布与运行监控；  
4. 安全能力升级：实现更完整的 RBAC、操作审计与数据脱敏；  
5. 评估能力升级：建立标准数据集回放、误报漏报指标与性能指标体系。  

总体来看，GoHIDS 作为一个面向主机安全场景的工程系统，已经具备较好的扩展基础和实践价值，可作为后续研究与产品化迭代的基础版本。

---

## 参考文献

### A. 国内论文（占多数）

[1] 李艳, 王纯子, 黄光球, 赵旭, 张斌, 李盈超. 网络安全态势感知分析框架与实现方法比较[J]. 电子学报, 2019, 47(4): 927-945. DOI:10.3969/j.issn.0372-2112.2019.04.021.  
[2] 裴祥喜, 孙晓磊, 李娜, 程睿怡, 贾相明. 计算机数据库入侵检测技术分析[J]. 河北水利电力学院学报, 2018, 28(1): 35-38. DOI:10.16046/j.cnki.issn1008-3782.2018.01.007.  
[3] 李银钊, 闫怀志, 张佳, 何海涛. 基于自适应模型的数据库入侵检测方法[J]. 北京理工大学学报, 2012, 32(3): 258-262.  
[4] 陈驰, 冯登国, 徐震, 等. 数据库事务恢复日志和入侵响应模型研究[J]. 计算机研究与发展, 2010, 47(10): 1797-1804.  
[5] 赵敏, 王红伟, 张涛, 等. AIB-DBIDM: 一种基于人工免疫的数据库入侵检测模型[J]. 计算机研究与发展, 2009, 46(z2): 487-493.  
[6] 朱建明, 马建峰. 基于容忍入侵的数据库安全体系结构[J]. 西安电子科技大学学报(自然科学版), 2003, 30(1): 85-89.  
[7] 谢美意, 朱虹, 冯玉才, 等. 自修复数据库系统设计实现关键问题研究[J]. 小型微型计算机系统, 2010, 31(10): 1926-1930.  
[8] 张华英. 利用混沌特征分析的大型Web数据库异常检测[J]. 科技通报, 2014(2): 215-217.  
[9] 张文安, 洪榛, 朱俊威, 陈博. 工业控制系统网络入侵检测方法综述[J]. 控制与决策, 2019.  
[10] 张志丽, 孙敏. 基于免疫网络的入侵检测模型构建[J]. 计算机工程, 2009, 35(8): 161-163. DOI:10.3969/j.issn.1000-3428.2009.08.054.  
[11] 李想, 王某某, 等. 基于攻击预测的网络安全态势量化方法[J]. 通信学报, 2017. DOI:10.11959/j.issn.1000-436x.2017204.  
[12] 张勇, 李舟军. 网络安全态势感知系统研究综述[J]. 计算机科学, 2016, 43(2): 11-17.  
[13] 李晓瑜, 李涛, 吴礼发. 基于大数据的网络安全态势感知技术研究[J]. 信息网络安全, 2015(9): 1-7.  
[14] 王伟, 李大辉. 基于大数据的网络安全态势感知研究[J]. 计算机科学, 2017, 44(S2): 372-375.  
[15] 邓淼磊, 阚雨培, 孙川川, 徐海航, 樊少珺, 周鑫. 基于深度学习的网络入侵检测系统综述[J]. 计算机应用, 2025, 45(2): 453-466.  

### B. 国外论文、标准与官方文档

[16] Denning D E. An Intrusion-Detection Model[J]. IEEE Transactions on Software Engineering, 1987, SE-13(2): 222-232.  
[17] Forrest S, Hofmeyr S A, Somayaji A, Longstaff T A. A Sense of Self for Unix Processes[C]//IEEE Symposium on Security and Privacy. 1996: 120-128.  
[18] Roesch M. Snort: Lightweight Intrusion Detection for Networks[C]//USENIX LISA. 1999: 229-238.  
[19] Provos N, Mazières D. A Future-Adaptable Password Scheme[C]//USENIX Annual Technical Conference. 1999.  
[20] Jones M, Bradley J, Sakimura N. JSON Web Token (JWT): RFC 7519[S]. IETF, 2015. DOI:10.17487/RFC7519.  
[21] Cichonski P, Millar T, Grance T, Scarfone K. Computer Security Incident Handling Guide: NIST SP 800-61 Rev.2[R]. 2012. DOI:10.6028/NIST.SP.800-61r2.  
[22] Open Information Security Foundation. Suricata User Guide[EB/OL]. https://docs.suricata.io/en/latest/  
[23] gRPC Authors. gRPC Documentation[EB/OL]. https://grpc.io/docs/  
[24] Google. Protocol Buffers Language Guide (proto3)[EB/OL]. https://protobuf.dev/programming-guides/proto3/  
[25] Gin Web Framework. Documentation[EB/OL]. https://gin-gonic.com/en/docs/  
[26] GORM Team. GORM Guides[EB/OL]. https://gorm.io/docs/  
[27] Oracle. MySQL 8.0 Reference Manual[EB/OL]. https://dev.mysql.com/doc/mysql/8.0/en/  
[28] Vue Team. Vue.js Guide[EB/OL]. https://vuejs.org/guide/introduction.html  
[29] Apache Software Foundation. Apache ECharts Documentation[EB/OL]. https://echarts.apache.org/en/index.html  

---

## 附录A 系统部署与运行流程（示意）

```mermaid
flowchart TD
  A[准备MySQL数据库 hids] --> B[启动Server: cmd/server/main.go]
  B --> C[启动Web前端: web]
  C --> D[启动Agent: cmd/agent/main.go]
  D --> E[Agent通过gRPC接入]
  E --> F[Web登录查看态势]
  F --> G[触发测试行为并验证告警]
```

## 附录B 软件工程工件清单（与本项目对应）

1. 需求规格说明：第3章；  
2. 总体架构设计：第4章 4.1~4.3；  
3. 数据库设计文档：第4章 4.4；  
4. 接口设计文档：第4章 4.5；  
5. 详细设计说明：第5章；  
6. 测试计划与结果：第6章；  
7. 维护与演进建议：第7章。  

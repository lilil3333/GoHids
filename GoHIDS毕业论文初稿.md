# 基于 GoHIDS 的主机入侵检测与可视化告警平台的设计与实现

## 摘要
随着政企内网与终端规模持续扩大，单纯依赖边界防护的安全体系难以及时发现主机侧异常行为。针对主机安全监测中“采集分散、联动不足、告警上下文不完整”等问题，本文设计并实现了一套基于 Go 语言的主机入侵检测平台 GoHIDS。系统采用 Agent/Server/Web 三层架构：Agent 侧负责进程、网络连接、文件、注册表、安全日志、USB、资产基线等多源数据采集；Server 侧基于 gRPC 双向流实现实时传输与任务下发，基于 Gin 提供 REST 接口，基于 GORM/MySQL 完成告警与事件持久化；Web 侧基于 Vue3 + Element Plus + ECharts 实现态势总览、主机详情、时间线与告警处置可视化。

在检测机制方面，系统引入“规则匹配 + 情报联动 + 自动取证”闭环：进程启动事件可与 Suricata 规则集解析结果进行匹配；外联公网 IP 可调用威胁情报进行恶意性研判；命中高风险场景后可自动下发取证任务，回传进程路径、命令行、父子进程关系与样本哈希。与此同时，系统实现资产基线快照与差异检测机制，用于识别端口、IP、主机属性等关键资产变化。本文围绕系统需求、总体架构、关键模块实现与测试过程进行阐述。实践结果表明，该系统能够在统一平台中完成主机数据采集、威胁发现、告警展示与取证联动，具备较好的工程可用性与扩展性。

**关键词**：主机入侵检测；安全监测；gRPC；威胁情报；自动取证；资产基线

---

## Abstract
As endpoint scale grows in enterprise networks, perimeter-only defense is insufficient for timely host-side threat discovery. To address issues such as fragmented telemetry, weak linkage, and limited alert context, this thesis designs and implements GoHIDS, a Go-based host intrusion detection platform. The system follows a three-tier architecture (Agent/Server/Web). Agents collect multi-source host telemetry including process, network, file, registry, security log, USB, and asset baseline data. The server uses bidirectional gRPC streaming for real-time transport and task dispatch, Gin for RESTful APIs, and GORM/MySQL for persistence. The web console built with Vue3, Element Plus, and ECharts provides dashboards for security operations.

GoHIDS implements a detection-and-response loop combining rule matching, threat-intelligence enrichment, and automated forensics. Process start events are matched against parsed Suricata-style rules. Outbound public IP connections are enriched by threat-intelligence queries. High-risk events trigger automated forensic tasks to collect executable path, command line, process lineage, and file hash evidence. In addition, the platform includes baseline snapshot and differential analysis for host assets, enabling change detection on ports, IPs, and host attributes. This thesis presents requirement analysis, system architecture, key implementation details, and testing methodology. Results indicate that the platform can effectively support unified host telemetry collection, threat detection, alerting, and forensic linkage with good engineering scalability.

**Keywords**: host intrusion detection; security monitoring; gRPC; threat intelligence; automated forensics; baseline drift

---

## 第1章 绪论

### 1.1 研究背景与意义
入侵检测模型的核心思想可追溯至 Denning 提出的异常检测框架，即通过审计数据中偏离“正常行为”的模式识别潜在入侵行为[1]。随着攻击手法向横向移动、驻留隐蔽与多阶段攻击演进，仅依赖网络边界告警已难以反映主机内部真实风险。主机侧检测（HIDS）能够覆盖进程执行、登录行为、文件与注册表变更等高价值信号，是安全运营体系中的关键能力。

在工程实践中，很多系统面临三个问题：一是数据孤岛，采集、告警、展示分散在不同工具；二是告警上下文不足，无法快速定位“哪个进程在何时做了什么”；三是处置链条断裂，检测与取证环节未形成自动闭环。本文围绕上述问题，构建 GoHIDS 平台，实现“采集-检测-告警-取证”的一体化流程。

### 1.2 国内外研究与技术现状
在理论研究方面，Denning 的模型奠定了异常检测基础[1]；Forrest 等提出基于系统调用序列的主机异常检测思想，为主机行为建模提供了方法参考[2]。在工程系统方面，Snort/Suricata 代表了规则驱动的检测路线[3][4]，其中 Suricata 在规则语言、协议解析和告警输出方面形成了成熟生态。认证与会话安全方面，JWT 已成为 API 鉴权的事实标准之一[5]；密码存储方面，bcrypt 的自适应成本机制被广泛采用[6]。  

现有开源平台功能强大但部署复杂、学习曲线较高。对于毕业设计场景，更适合构建一个结构清晰、可二次开发、覆盖完整闭环的小型可运行系统。GoHIDS 即在此目标下实现。

### 1.3 研究内容与论文结构
本文主要工作包括：
1. 设计 Agent/Server/Web 三层体系与数据流转机制。
2. 实现主机多源采集与统一协议传输。
3. 实现规则匹配、威胁情报联动与自动取证机制。
4. 实现资产基线快照与差异检测。
5. 完成可视化平台与基础功能验证。

全文结构如下：第2章介绍关键技术；第3章进行需求分析；第4章给出系统设计；第5章说明核心实现；第6章给出测试与分析；第7章总结与展望。

---

## 第2章 关键技术与理论基础

### 2.1 主机入侵检测与异常行为分析
主机入侵检测关注操作系统与应用运行时行为。与网络侧检测相比，主机侧更容易获得进程、用户、文件和日志等语义信息。本文在工程上采用“事件驱动 + 周期采集”混合方式：周期扫描用于构建全局视图，事件差异用于发现变化与异常。

### 2.2 gRPC 与 Protocol Buffers
gRPC 提供基于 HTTP/2 的高性能 RPC 与流式通信能力[7]。Protocol Buffers 提供跨语言、紧凑高效的数据结构定义方式[8]。GoHIDS 在 `pkg/protocol/grpc.proto` 中定义 `RawData`、`Record`、`Command` 等消息，通过 `Transfer(stream RawData) returns (stream Command)` 实现 Agent 与 Server 的双向流通信，兼顾实时上报与远程任务下发。

### 2.3 Web 与服务端技术栈
后端采用 Gin 构建 HTTP API[9]，结合 JWT 进行鉴权[5]；数据访问层采用 GORM 实现模型映射与自动迁移[10]，存储引擎使用 MySQL InnoDB 事务模型[11]。前端采用 Vue3 组件化开发[12]，UI 使用 Element Plus，图表使用 Apache ECharts[13] 完成态势可视化。

### 2.4 安全实现相关技术
密码散列使用 bcrypt[6]；应急响应流程参考 NIST 事件处置框架[14]；威胁检测规则语义参照 Suricata 规则体系[4]。这些技术共同支撑了系统在“鉴权、检测、研判、响应”各环节的可落地实现。

---

## 第3章 需求分析

### 3.1 功能需求
结合代码实现，系统功能需求可归纳为：
1. 主机资产与状态监测：主机在线状态、IP、OS、端口、用户等。
2. 运行行为监测：进程启动/退出、网络连接建立/断开、文件变更、注册表变更。
3. 安全事件与告警：安全日志事件解析、规则命中告警、恶意 IP 连接告警。
4. 响应联动：服务端向指定 Agent 下发取证任务并回传结果。
5. 可视化与运维：Dashboard 总览、主机详情、告警列表、事件导出。

### 3.2 非功能需求
1. 实时性：采集端按 10~60 秒粒度上报，支持准实时监测。
2. 可扩展性：采集器插件化管理，便于新增数据类型。
3. 可靠性：连接断开后支持重连；核心数据落库存储。
4. 安全性：登录鉴权、受保护 API、密码哈希存储。

### 3.3 可行性分析
技术可行性：Go 语言生态下 gRPC、Gin、GORM、gopsutil 组件成熟，具备快速实现条件。  
经济可行性：基于开源组件构建，无额外商业授权成本。  
实施可行性：代码结构清晰，前后端解耦，适合课程设计与后续迭代。

---

## 第4章 系统总体设计

### 4.1 总体架构
系统采用三层架构：
1. Agent 层：运行于被监控主机，负责数据采集与本地基线维护。
2. Server 层：负责接收数据、检测分析、告警落库、任务下发、API 服务。
3. Web 层：负责数据展示、交互查询与策略配置。

其中 Agent 与 Server 通过 gRPC 双向流通信，Web 与 Server 通过 HTTP/JSON 交互。

### 4.2 模块划分
1. 采集模块（`internal/agent/collector/*`）：心跳、进程、网络、性能、文件、注册表、安全日志、USB、端口、用户、基线、取证。
2. 传输模块（`internal/agent/transport`、`internal/server/grpc`）：双向流传输与命令回传。
3. 服务模块（`internal/server/service`）：数据处理、缓存维护、告警生成、情报查询与取证触发。
4. 持久化模块（`internal/server/repository` + `internal/server/model`）：事件、告警、资产、用户等数据管理。
5. 表现模块（`web/src/views`、`web/src/components`）：总览、主机、告警与详情面板。

### 4.3 数据库设计
系统核心实体包括：`Agent`、`SecurityEvent`、`Alert`、`ProcessEvent`、`NetworkEvent`、`FileEvent`、`AssetPort`、`AssetUser`、`AssetChange`、`User`。  
设计思想为“事件流水 + 资产快照并存”：事件表保留时序，资产表保存当前状态，满足溯源与态势展示双重需求。

### 4.4 接口与权限设计
API 分为公共接口与鉴权接口：登录接口 `/api/login` 为公开；其余接口通过 JWT 中间件保护。业务接口覆盖 Dashboard、主机列表、告警查询、资产变更、时间线查询与数据导出，满足安全运营常用场景。

---

## 第5章 系统详细实现

### 5.1 Agent 端实现
在 `cmd/agent/main.go` 中，系统注册并启动多类 Collector，由管理器统一调度。各采集器将结果封装为 `RawData` 后写入通道，由发送协程统一上报。

#### 5.1.1 进程采集与规则匹配
`process.go` 每 10 秒扫描进程，构建当前进程映射与历史映射差异，生成 `START/EXIT` 事件。新进程启动时调用 `RuleEngine.MatchProcess` 进行规则匹配，命中后上报 `DataTypeIntrusion` 入侵事件，携带规则 SID、进程名、路径、命令行及父进程信息，形成高语义告警上下文。

#### 5.1.2 网络连接监测与上下文补全
`network.go` 每 10 秒采集连接状态，识别 `CONNECT/DISCONNECT` 事件；对每条连接补全 `process_name`、`process_path`、`cmdline` 等字段，为后续恶意外联定位提供依据。

#### 5.1.3 资产基线与差异检测
`baseline.go` 首次运行时生成本地基线文件 `baseline.json`，后续周期采集主机快照并与旧基线比较，识别主机名、OS、内核、IP、监听端口等变化，按 `ADD/DELETE/MODIFY` 规则生成资产变更事件。

#### 5.1.4 远程取证执行
`forensic.go` 维护任务队列，接收服务端下发的目标 IP 后，关联网络连接定位进程，提取可执行文件路径、命令行、父子进程关系并计算 SHA-256，最终将结构化取证报告回传服务端。

### 5.2 Server 端实现

#### 5.2.1 流式接收与缓存更新
`internal/server/grpc/server.go` 在收到首包后注册 Agent 流，后续持续接收 `RawData`。`service.ProcessData` 负责更新内存态缓存与数据库 Agent 状态，并按数据类型分发至不同处理函数。

#### 5.2.2 检测与告警生成链路
1. 进程事件入库 `ProcessEvent`，并更新在线进程状态。
2. 网络事件入库 `NetworkEvent`，并维护当前活动连接。
3. 文件/注册表/安全日志等事件写入 `SecurityEvent`，高风险场景写入 `Alert`。
4. 对外联公网 IP 进行情报查询，若判定恶意则写入高危告警并触发自动取证命令。

#### 5.2.3 鉴权与接口服务
系统在启动阶段初始化 JWT；用户登录成功后签发 Token。Gin 路由中，`/api/login` 为公开接口，其他接口经 `JWTAuthMiddleware` 校验后访问，实现基础访问控制。

### 5.3 Web 端实现
前端通过 `axios` 统一封装请求与鉴权头处理。`Home.vue` 展示在线主机、告警趋势、OS 分布、Top 进程与情报开关；`Agents.vue` 提供主机详情多标签页（进程、连接、端口、用户、服务、注册表）；`Alerts.vue` 提供告警列表与导出入口。可视化层通过 ECharts 提升了安全数据的可读性与研判效率。

### 5.4 关键实现特征总结
1. 基于 gRPC 双向流实现“数据上报 + 指令下发”统一通道。
2. 基于事件差分机制降低全量传输开销并保留行为语义。
3. 基于“检测-告警-取证”闭环提升告警可解释性与可处置性。
4. 基于资产基线机制支持持续漂移检测与主机资产盘点。

---

## 第6章 系统测试与结果分析

### 6.1 测试环境
系统采用 Windows 主机部署 Agent，Server 与 MySQL 本地部署，Web 前端通过 Vite 启动。测试重点为功能正确性与链路连通性验证。

### 6.2 功能测试场景
1. **Agent 上线与状态展示**：启动 Agent 后，主机列表可显示在线状态与最近心跳时间。
2. **进程与网络事件采集**：新建/退出进程、建立/断开连接后，时间线可见对应事件。
3. **安全日志告警生成**：触发失败登录后，可在告警页看到登录失败相关告警。
4. **恶意连接联动处置**：当外联命中恶意情报时，系统生成高危告警并触发取证任务，取证结果可作为安全事件入库。
5. **资产基线变更识别**：端口状态变化后，资产变更列表出现新增/删除记录。
6. **接口鉴权验证**：未携带 Token 请求受保护接口会被拒绝。

### 6.3 测试结论与问题分析
测试表明系统主链路可正常工作，能够实现多源采集、统一展示与联动取证。当前仍存在以下改进空间：  
1. 缺少高并发压测与长稳测试数据。  
2. 规则匹配主要基于关键字，复杂行为关联能力有待增强。  
3. 资产用户信息受底层 API 限制，跨平台一致性需进一步优化。  

---

## 第7章 总结与展望

本文面向主机安全监测需求，设计并实现了 GoHIDS 平台。系统以 Go 生态为基础，完成了 Agent 采集、gRPC 流式传输、服务端检测与告警、Web 可视化展示、威胁情报联动与自动取证等核心能力。相比仅做日志采集或静态展示的实现方式，GoHIDS 在检测闭环与处置联动方面更完整，能够为安全运维提供更具可操作性的主机侧证据。

后续工作可围绕以下方向展开：  
1. 增加规则引擎语义能力，支持时序关联与多事件聚合。  
2. 引入消息队列与分布式存储，提升大规模主机接入能力。  
3. 完善多平台采集适配，增强 Linux/Windows 一致性。  
4. 增强误报抑制与告警优先级模型，提升运营效率。  
5. 建立自动化测试与性能基准体系，形成可量化评估报告。  

---

## 参考文献

[1] Denning D E. An Intrusion-Detection Model[J]. IEEE Transactions on Software Engineering, 1987, SE-13(2): 222-232.  
[2] Forrest S, Hofmeyr S A, Somayaji A, et al. A Sense of Self for Unix Processes[C]//Proceedings of the 1996 IEEE Symposium on Security and Privacy. 1996: 120-128.  
[3] Roesch M. Snort: Lightweight Intrusion Detection for Networks[C]//Proceedings of the 13th USENIX Conference on System Administration (LISA). 1999: 229-238.  
[4] Open Information Security Foundation. Suricata User Guide[EB/OL]. https://docs.suricata.io/en/latest/  
[5] Jones M, Bradley J, Sakimura N. JSON Web Token (JWT): RFC 7519[S]. IETF, 2015. DOI:10.17487/RFC7519.  
[6] Provos N, Mazières D. A Future-Adaptable Password Scheme[C]//1999 USENIX Annual Technical Conference. 1999.  
[7] gRPC Authors. Introduction to gRPC[EB/OL]. https://grpc.io/docs/what-is-grpc/introduction/  
[8] Google. Protocol Buffers Language Guide (proto3)[EB/OL]. https://protobuf.dev/programming-guides/proto3/  
[9] Gin Web Framework. Documentation[EB/OL]. https://gin-gonic.com/en/docs/  
[10] GORM Team. GORM Guides[EB/OL]. https://gorm.io/docs/  
[11] Oracle. MySQL 8.0 Reference Manual[EB/OL]. https://dev.mysql.com/doc/mysql/8.0/en/  
[12] Vue Team. Vue.js Guide[EB/OL]. https://vuejs.org/guide/introduction.html  
[13] Apache Software Foundation. Apache ECharts[EB/OL]. https://echarts.apache.org/en/  
[14] Cichonski P, Millar T, Grance T, et al. Computer Security Incident Handling Guide: NIST SP 800-61 Rev.2[R]. 2012. DOI:10.6028/NIST.SP.800-61r2.


# 网络拓扑自动生成管理系统

> 通过 SNMP + SSH 协议自动发现网络设备并生成可视化拓扑图（LLDP MIB 采集）

---

## 项目结构

```
app/
├── index.html              # 前端页面（双击打开即可）
├── backend/
│   └── server.js           # Node.js 后端 API
├── package.json
└── README.md
```

---

## 快速开始

### 仅前端（演示模式）

直接双击 `index.html` 用浏览器打开，点击 **"加载演示数据"** 查看效果，无需启动后端。

### 完整模式

**1. 安装依赖**

```bash
cd app
npm install
```

**2. 启动后端**

```bash
node backend/server.js
```

访问 http://localhost:5000/api/health 验证是否正常。

**3. 打开前端**

双击 `index.html` 打开浏览器页面，填写 IP 范围和 SNMP Community，点击扫描。

---

## 功能

| 功能 | 说明 |
|------|------|
| IP 范围扫描 | 支持 `x.x.x.x-x.x.x.y`、CIDR、逗号分隔 |
| SNMP LLDP 采集 | 通过 LLDP MIB 自动发现邻居（主要采集方式） |
| SSH 采集 | 支持华为/思科/H3C/锐捷（可选，非必须） |
| 接口速率识别 | 从 ifSpeed + 端口名推断链路带宽 |
| 拓扑可视化 | SVG 视图，支持拖拽、缩放 |
| 设备列表 | 表格展示设备状态、邻居数 |
| 链路管理 | 链路两端端口、类型、速率 |
| 导出 SVG | 一键导出拓扑图 |

---

## 支持的设备

| 厂商 | 系列 | SNMP | SSH |
|------|------|------|-----|
| 锐捷 | RG-S 系列 | ✅ | ✅ |
| 华为 | S 系列 | ✅ | ✅ |
| 思科 | Catalyst / Nexus | ✅ | ✅ |
| H3C | S 系列 | ✅ | ✅ |

---

## 交换机配置要求

**SNMP（必须）**
```
# 锐捷
snmp-server community public ro

# 华为
snmp-agent community read public

# 思科
snmp-server community public ro
```

**LLDP（必须）**
```
# 锐捷
lldp enable
interface range GigabitEthernet 0/1 - 48
  lldp mode tx-rx

# 华为
lldp enable

# 思科
lldp run
```

**SSH（可选）**
```
# 锐捷
username admin privilege 15 password ruijie@123
line vty 0 4
  login local
  transport input ssh
```

---

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/scan` | POST | 批量扫描 IP 范围 |
| `/api/topology` | GET | 获取拓扑数据 |
| `/api/topology/demo` | GET | 演示拓扑数据 |

---

## 常见问题

**Q: 扫描不到设备？**
A: 确认 SNMP Community 正确，设备 161 端口可达。

**Q: 拓扑链路为空？**
A: 确认交换机已开启 LLDP（`show lldp neighbors` 有数据）。

**Q: 链路速率不对？**
A: LLDP MIB 的 ifSpeed 字段在自动协商状态下可能返回 4294967295（0xFFFFFFFF），系统会结合端口名推断。

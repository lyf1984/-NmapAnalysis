### **整体结构**

```
{
  "nodes": [...],  // 节点列表，包括设备、路由器和子网
  "edges": [...]   // 边列表，包括设备、路由器和子网之间的连接
}
```

### **节点信息（Nodes）**

#### **节点属性**

| 字段名        | 数据类型 | 描述                                                         | 必需 | 示例                    |
| ------------- | -------- | ------------------------------------------------------------ | ---- | ----------------------- |
| `node_id`     | `string` | 节点的唯一标识符，通常为 IP 地址、子网地址或主机名           | 是   | `"192.168.1.0/24"`      |
| `node_type`   | `string` | 节点类型，可选值包括 `device`、`router` 或 `subnet`          | 是   | `"subnet"`              |
| `state`       | `string` | 节点状态，例如 `up` 或 `down`（仅对设备或路由器节点有效）    | 否   | `"up"`                  |
| ~~`children`~~    | ~~`array`~~  | ~~子节点的列表，表示子网内的设备或子网（仅对 `subnet` 类型节点有效）~~ | ~~否~~   | ~~`["192.168.1.10", ...]`~~ |
| `fqdn`        | `string` | 完全限定域名（如果可用）                                     | 否   | `"example.com"`         |
| `reverse_dns` | `string` | 反向 DNS（如果可用）                                         | 否   | `"server.example.com"`  |
| `mac_address` | `string` | MAC 地址（如果可用）                                         | 否   | `"00:14:22:01:23:45"`   |
| `vendor`      | `string` | 设备供应商（如果可用）                                       | 否   | `"Cisco"`               |
| `open_ports`  | `array`  | 开放端口列表（TCP/UDP）                                      | 否   | `[80, 443]`             |
| `os`          | `string` | 操作系统（如果可用）                                         | 否   | `"Linux 4.15"`          |

#### **节点示例**

**设备节点（`device`）：**

```
{
  "node_id": "192.168.1.10",
  "node_type": "device",
  "state": "up",
  "fqdn": "host1.example.com",
  "reverse_dns": "host1.reverse.example.com",
  "mac_address": "00:14:22:01:23:45",
  "vendor": "Cisco",
  "open_ports": [22, 80],
  "os": "Linux 4.15"
}
```

**路由器节点（`router`）：**

```
{
  "node_id": "192.168.1.1",
  "node_type": "router",
  "state": "up",
  "fqdn": "router.example.com",
  "reverse_dns": "router.reverse.example.com",
  "mac_address": "00:25:64:3A:9B:02",
  "vendor": "Juniper",
  "open_ports": [80, 443],
  "os": "JunOS 15.1"
}
```

**子网节点（`subnet`）：**

```
{
  "node_id": "192.168.1.0/24",
  "node_type": "subnet",
  "children": [
    {
      "node_id": "192.168.1.10",
      "node_type": "device",
      "state": "up",
      "fqdn": "host1.example.com",
      "reverse_dns": "host1.reverse.example.com",
      "mac_address": "00:14:22:01:23:45",
      "vendor": "Cisco",
      "open_ports": [22, 80],
      "os": "Linux 4.15"
    },
    {
      "node_id": "192.168.1.20",
      "node_type": "device",
      "state": "down",
      "fqdn": "host2.example.com",
      "reverse_dns": "host2.reverse.example.com",
      "mac_address": "00:14:22:01:23:46",
      "vendor": "HP",
      "open_ports": [443],
      "os": "Windows 10"
    }
  ]
}
```

### **边信息（Edges）**

#### **边属性**

| 字段名      | 数据类型 | 描述                                                   | 必需 | 示例               |
| ----------- | -------- | ------------------------------------------------------ | ---- | ------------------ |
| `from_node` | `string` | 边的起点节点 ID（对应 `node_id`）                      | 是   | `"192.168.1.0/24"` |
| `to_node`   | `string` | 边的终点节点 ID（对应 `node_id`）                      | 是   | `"192.168.1.1"`    |
| `edge_type` | `string` | 边的类型，表示连接关系（如 `traceroute` 或 `logical`） | 是   | `"logical"`        |
| `protocol`  | `string` | 使用的协议（如 `TCP`, `UDP` 等）                       | 否   | `"TCP"`            |
| `layer`     | `string` | 网络层次（如 `Layer 2`, `Layer 3`）                    | 否   | `"Layer 3"`        |

#### **边示例**

- **逻辑连接（子网与设备）：**

```
{
  "from_node": "192.168.1.0/24",
  "to_node": "192.168.1.10",
  "edge_type": "logical",
  "protocol": "IP",
  "layer": "Layer 3"
}
```

- **路由连接（路由器与设备）：**

```
{
  "from_node": "192.168.1.1",
  "to_node": "192.168.1.10",
  "edge_type": "traceroute",
  "protocol": "ICMP",
  "layer": "Layer 3"
}
```


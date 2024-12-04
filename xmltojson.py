import json
import xml.etree.ElementTree as ET


class NmapParser:
    def __init__(self, localhost_ip="127.0.0.1"):
        self.localhost_ip = localhost_ip
        self.nodes = []
        self.edges = []
        self.added_edges = set()  # 用于跟踪已添加的边，避免重复边

    def parse(self, file_path):
        """解析 Nmap XML 文件，提取节点和边的信息"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # 添加本机节点（localhost）
            self._add_localhost_node()

            # 遍历主机信息
            for host in root.findall("host"):
                self._parse_host(host)

            return {"nodes": self.nodes, "edges": self.edges}

        except ET.ParseError as e:
            print(f"XML 解析错误: {e}")
            return None
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
            return None

    def save_to_json(self, data, output_file):
        """将数据保存为 JSON 文件"""
        try:
            with open(output_file, "w") as f:
                json.dump(data, f, indent=4)
            print(f"数据成功保存到 {output_file}")
        except IOError as e:
            print(f"保存 JSON 文件失败: {e}")

    def _add_localhost_node(self):
        """添加本机节点信息"""
        self.nodes.append({
            "node_id": self.localhost_ip,
            "node_type": "device",
            "state": "up",
            "fqdn": "localhost.local",
            "reverse_dns": "localhost.reverse.local",
            "mac_address": "00:00:00:00:00:00",
            "vendor": "Unknown",
            "open_ports": [22, 80],
            "os": "Linux"
        })

    def _parse_host(self, host):
        """解析单个主机信息"""
        ip_element = host.find("address")
        ip_address = ip_element.get("addr") if ip_element is not None else "Unknown"
        state_element = host.find("status")
        state = state_element.get("state") if state_element is not None else "Unknown"

        fqdn = host.find("hostnames")
        if fqdn is not None:
            hostname = fqdn.find("hostname")
            fqdn = hostname.get("name") if hostname is not None else None
        else:
            fqdn = None

        reverse_dns = ip_address  # 默认将 IP 作为反向 DNS

        # 获取操作系统信息
        os_element = host.find("os-fingerprint")
        os = "Unknown"
        if os_element is not None:
            os = os_element.find("osmatch").get("name") if os_element.find("osmatch") is not None else "Unknown"

        mac_element = host.find("address[@addrtype='mac']")
        mac_address = mac_element.get("addr") if mac_element is not None else "00:00:00:00:00:00"

        # 提取端口信息
        open_ports = self._parse_ports(host)

        # 生成节点信息
        self.nodes.append({
            "node_id": ip_address,
            "node_type": "device",
            "state": state,
            "fqdn": fqdn,
            "reverse_dns": reverse_dns,
            "mac_address": mac_address,
            "vendor": "Unknown",
            "open_ports": open_ports,
            "os": os
        })

        # 生成边信息
        self._parse_edges(host)

    def _parse_ports(self, host):
        """提取开放端口信息"""
        open_ports = []
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            protocol = port.get("protocol")
            state_element = port.find("state")
            state = state_element.get("state") if state_element is not None else "unknown"
            service_element = port.find("service")
            service_name = service_element.get("name") if service_element is not None else "unknown"
            version = service_element.get("version") if service_element is not None else "unknown"

            if state == "open":  # 仅记录开放的端口
                open_ports.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "version": version
                })
        return open_ports

    def _parse_edges(self, host):
        """解析边信息"""
        trace = host.find("trace")
        if trace is not None:
            prev_hop = None
            for hop in trace.findall("hop"):
                hop_ip = hop.get("ipaddr")
                if hop_ip and (prev_hop, hop_ip) not in self.added_edges:
                    self.edges.append({
                        "from_node": prev_hop if prev_hop else self.localhost_ip,
                        "to_node": hop_ip,
                        "edge_type": "traceroute",
                        "protocol": "ICMP",
                        "layer": "Layer 3"
                    })
                    self.added_edges.add((prev_hop, hop_ip))
                    prev_hop = hop_ip


def main():
    # 输入 XML 文件路径
    input_file = "./xml/126.xml"  # 替换为实际的 nmap 扫描结果文件路径
    output_file = "new.json"  # 输出 JSON 文件名

    # 创建解析器实例
    parser = NmapParser()

    # 解析 XML 并提取数据
    network_data = parser.parse(input_file)
    if network_data:
        # 保存为 JSON
        parser.save_to_json(network_data, output_file)


if __name__ == "__main__":
    main()

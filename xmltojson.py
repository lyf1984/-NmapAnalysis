import json
import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path, localhost_ip="127.0.0.1"):
    """解析 Nmap XML 文件，提取节点和边的信息"""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        nodes = []
        edges = []
        added_edges = set()  # 用于跟踪已添加的边，避免重复边

        # 添加本机节点（localhost），并假定本机始终在线
        nodes.append({
            "node_id": localhost_ip,
            "node_type": "device",
            "state": "up",
            "fqdn": "localhost.local",
            "reverse_dns": "localhost.reverse.local",
            "mac_address": "00:00:00:00:00:00",
            "vendor": "Unknown",
            "open_ports": [22, 80],
            "os": "Linux"
        })

        # 遍历主机信息
        for host in root.findall("host"):
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
            reverse_dns = host.find("address").get("addr")  # 这里假设是反向 DNS 的处理
            
            mac_element = host.find("hostnames")
            mac_address = mac_element.get("addr") if mac_element else "00:00:00:00:00:00"

            # 生成节点信息
            nodes.append({
                "node_id": ip_address,
                "node_type": "device",
                "state": state,
                "fqdn": fqdn,
                "reverse_dns": reverse_dns,
                "mac_address": mac_address,
                "vendor": "Unknown",
                "open_ports": [80, 443],  # 假定某些端口开放
                "os": "Unknown"
            })

            # 生成边信息
            trace = host.find("trace")
            if trace is not None:
                prev_hop = None
                for hop in trace.findall("hop"):
                    hop_ip = hop.get("ipaddr")
                    if hop_ip:
                        edges.append({
                            "from_node": prev_hop if prev_hop else localhost_ip,
                            "to_node": hop_ip,
                            "edge_type": "traceroute",
                            "protocol": "ICMP",
                            "layer": "Layer 3"
                        })
                        prev_hop = hop_ip

        return {"nodes": nodes, "edges": edges}

    except ET.ParseError as e:
        print(f"XML 解析错误: {e}")
        return None
    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
        return None

def save_to_json(data, output_file):
    """将数据保存为 JSON 文件"""
    try:
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)
        print(f"数据成功保存到 {output_file}")
    except IOError as e:
        print(f"保存 JSON 文件失败: {e}")

def main():
    # 输入 XML 文件路径
    input_file = "nmap_result.xml"  # 替换为实际的 nmap 扫描结果文件路径
    output_file = "network_topology.json"  # 输出 JSON 文件名

    # 解析 XML 并提取数据
    network_data = parse_nmap_xml(input_file)
    if network_data:
        # 保存为 JSON
        save_to_json(network_data, output_file)

if __name__ == "__main__":
    main()

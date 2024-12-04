import json
import xml.etree.ElementTree as ET
from Node import Node
from Edge import Edge


class NmapParser:
    """
    Nmap XML 数据解析器。

    该类用于解析 Nmap 生成的 XML 文件，并提取网络节点和边的信息。
    提取的信息包括节点的属性、开放端口列表，以及边的类型、协议和层级。
    """

    def __init__(self):
        """
        初始化 NmapParser。

        属性:
            - nodes (List[Node]): 存储解析出的 Node 对象。
            - edges (List[Edge]): 存储解析出的 Edge 对象。
            - added_nodes (set[int]): 存储已添加的 Node 对象的哈希值，用于去重。
            - added_edges (set[int]): 存储已添加的 Edge 对象的哈希值，用于去重。
        """
        self.nodes: list[Node] = []  # 存储 Node 实例的列表
        self.edges: list[Edge] = []  # 存储 Edge 实例的列表
        self.added_edges: set[int] = set()  # 用于跟踪已添加的 Edge 哈希值，避免重复边
        self.added_nodes: set[int] = set()  # 用于跟踪已添加的 Node 哈希值，避免重复节点

    def parse(self, file_path: str, localhost_node: Node) -> None:
        """
        解析 Nmap XML 文件，并动态传入 localhost 节点信息。

        :param file_path: str
            Nmap XML 文件路径。
        :param localhost_node: Node
            表示 localhost 的 Node 实例。
        """
        try:
            # 解析 XML 文件
            tree = ET.parse(file_path)
            root = tree.getroot()

            # 动态更新或添加 localhost 节点
            if hash(localhost_node) not in self.added_nodes:
                self.nodes.append(localhost_node)
                self.added_nodes.add(hash(localhost_node))

            # 遍历主机信息
            for host in root.findall("host"):
                self._parse_host(host, localhost_node)

        except ET.ParseError as e:
            print(f"XML 解析错误: {e}")
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")

    def save_to_json(self, output_file: str) -> None:
        """
        将节点和边数据保存为 JSON 文件。

        :param output_file: str
            输出 JSON 文件的路径。
        """
        try:
            # 将 Node 和 Edge 对象转换为字典列表
            data = {
                "nodes": [node.to_dict() for node in self.nodes],
                "edges": [edge.to_dict() for edge in self.edges]
            }

            # 写入 JSON 文件
            with open(output_file, "w") as f:
                json.dump(data, f, indent=4)
            print(f"数据成功保存到 {output_file}")
        except IOError as e:
            print(f"保存 JSON 文件失败: {e}")

    def _add_localhost_node(self, localhost_info: Node) -> None:
        """
        动态添加或更新本机节点信息。

        :param localhost_info: Node
            表示 localhost 的 Node 实例。
        """
        if hash(localhost_info) not in self.added_nodes:
            self.nodes.append(localhost_info)
            self.added_nodes.add(hash(localhost_info))

    def _parse_host(self, host: ET.Element, localhost_node: Node) -> None:
        """
        解析单个主机信息。

        :param host: ET.Element
            XML 主机节点。
        :param localhost_node: Node
            表示 localhost 的 Node 实例。
        """
        # 获取 IP 地址
        ip_element = host.find("address")
        ip_address = ip_element.get("addr") if ip_element is not None else "Unknown"

        # 检查是否已存在
        node_hash = hash(ip_address)  # 使用 IP 地址计算哈希值
        if node_hash in self.added_nodes:
            return  # 避免重复添加节点

        # 获取状态
        state_element = host.find("status")
        state = state_element.get("state") if state_element is not None else "Unknown"

        # 获取 FQDN
        fqdn = None
        hostnames_element = host.find("hostnames")
        if hostnames_element is not None:
            hostname = hostnames_element.find("hostname")
            fqdn = hostname.get("name") if hostname is not None else None

        # 默认反向 DNS
        reverse_dns = ip_address

        # 获取操作系统信息
        os = "Unknown"
        os_element = host.find("os")
        if os_element is not None:
            os_match = os_element.find("osmatch")
            os = os_match.get("name") if os_match is not None else "Unknown"

        # 获取 MAC 地址
        mac_address = "00:00:00:00:00:00"
        mac_element = host.find("address[@addrtype='mac']")
        if mac_element is not None:
            mac_address = mac_element.get("addr")

        # 提取开放端口信息
        open_ports = self._parse_ports(host)

        # 创建 Node 对象
        node = Node(
            node_id=ip_address,
            node_type="device",
            state=state,
            fqdn=fqdn,
            reverse_dns=reverse_dns,
            mac_address=mac_address,
            vendor="Unknown",
            open_ports=open_ports,
            os=os
        )

        # 添加节点
        self.nodes.append(node)
        self.added_nodes.add(node_hash)

        # 解析并生成边信息
        self._parse_edges(host, localhost_node)

    def _parse_ports(self, host: ET.Element) -> list[dict]:
        """
        提取开放端口信息。

        :param host: ET.Element
            XML 主机节点。
        :return: list[dict]
            包含端口信息的列表，格式为：
            [
                {
                    "port": int,
                    "protocol": str,
                    "service": str,
                    "version": Optional[str]
                },
                ...
            ]
        """
        open_ports = []

        for port in host.findall(".//port"):
            port_id = port.get("portid")  # 获取端口号
            protocol = port.get("protocol")  # 获取协议类型

            # 获取端口状态
            state_element = port.find("state")
            state = state_element.get("state") if state_element is not None else "unknown"

            # 获取服务名称和版本
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

    def _parse_edges(self, host: ET.Element, localhost_node: Node) -> None:
        """
        解析边信息，并将边添加到边列表中。

        :param host: ET.Element
            XML 主机节点。
        :param localhost_node: Node
            表示 localhost 的 Node 实例。
        """
        trace = host.find("trace")
        if trace is not None:
            # 初始设置为 localhost 节点的 ID
            prev_hop = localhost_node.node_id

            # 遍历 trace 中的 hop
            for hop in trace.findall("hop"):
                hop_ip = hop.get("ipaddr")  # 获取 hop 的 IP 地址

                if hop_ip:  # 如果 hop IP 存在
                    # 创建 Edge 实例
                    edge = Edge(
                        from_node=prev_hop,
                        to_node=hop_ip,
                        edge_type="traceroute",
                        protocol="ICMP",
                        layer="Layer 3"
                    )

                    # 检查是否已经存在此边
                    if hash(edge) not in self.added_edges:
                        self.edges.append(edge)
                        self.added_edges.add(hash(edge))

                    # 更新 prev_hop 为当前 hop_ip
                    prev_hop = hop_ip

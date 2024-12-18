from Node import Node
from Edge import Edge
from NmapParser import NmapParser


def main():
    """
    主函数，解析多个 Nmap XML 文件并保存为 JSON。
    """
    inputs = [
        ("./xml/222_20_126.xml", Node(
            node_id="10.12.189.18",
            node_type="device",
            state="up",
            fqdn="unknown.local",
            reverse_dns="unknown.local",
            mac_address="00:00:00:00:00:00",
            vendor="Unknown",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": None},
                {"port": 443, "protocol": "tcp", "service": "https", "version": None}
            ],
            os="Linux"
        )),
        ("./xml/10_12_188.xml", Node(
            node_id="192.168.40.193",
            node_type="device",
            state="up",
            fqdn="unknown.local",
            reverse_dns="unknown.local",
            mac_address="00:00:00:00:00:00",
            vendor="Unknown",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": None}
            ],
            os="Linux"
        )),
        ("./xml/10_12_189.xml", Node(
            node_id="192.168.31.104",
            node_type="device",
            state="up",
            fqdn="unknown.local",
            reverse_dns="unknown.local",
            mac_address="00:00:00:00:00:00",
            vendor="Unknown",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": None}
            ],
            os="Linux"
        )),
        ("./xml/10_12_190.xml", Node(
            node_id="192.168.40.193",
            node_type="device",
            state="up",
            fqdn="unknown.local",
            reverse_dns="unknown.local",
            mac_address="00:00:00:00:00:00",
            vendor="Unknown",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": None}
            ],
            os="Linux"
        )),
        ("./xml/10_12_191.xml", Node(
            node_id="192.168.40.193",
            node_type="device",
            state="up",
            fqdn="unknown.local",
            reverse_dns="unknown.local",
            mac_address="00:00:00:00:00:00",
            vendor="Unknown",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": None}
            ],
            os="Linux"
        ))
    ]
    output_file = "output.json"  # 输出 JSON 文件名

    # 创建解析器实例
    parser = NmapParser()

    # 解析多个 XML 文件
    for file_path, localhost_node in inputs:
        parser.parse(file_path, localhost_node)

    # 保存为 JSON
    parser.save_to_json(output_file)


if __name__ == "__main__":
    main()

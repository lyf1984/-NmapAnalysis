from typing import List, Dict, Optional


class Node:
    def __init__(self, node_id: str, node_type: str, state: str, fqdn: Optional[str], reverse_dns: str,
                 mac_address: str, vendor: str, open_ports: List[Dict[str, Optional[str]]], os: Optional[str]):
        """
        初始化 Node 类实例，表示网络中的一个节点。

        :param node_id: str
            节点的唯一标识符（通常为 IP 地址）。
        :param node_type: str
            节点的类型，例如 "device"、"router"。
        :param state: str
            节点的状态，例如 "up" 或 "down"。
        :param fqdn: Optional[str]
            节点的完全限定域名（FQDN），可以为 None。
        :param reverse_dns: str
            节点的反向 DNS 名称。
        :param mac_address: str
            节点的 MAC 地址。
        :param vendor: str
            节点的设备供应商名称，例如 "Cisco"。
        :param open_ports: List[Dict[str, Optional[str]]]
            节点的开放端口列表，格式为：
            [
                {
                    "port": int,
                    "protocol": str,
                    "service": str,
                    "version": Optional[str]
                },
                ...
            ]
        :param os: Optional[str]
            节点的操作系统信息，可以为 None。
        """
        self.node_id = node_id
        self.node_type = node_type
        self.state = state
        self.fqdn = fqdn
        self.reverse_dns = reverse_dns
        self.mac_address = mac_address
        self.vendor = vendor
        self.open_ports = open_ports
        self.os = os

    def to_dict(self) -> dict:
        """
        将 Node 对象转换为字典格式，用于 JSON 序列化。

        :return: dict 包含节点属性的字典。
        """
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "state": self.state,
            "fqdn": self.fqdn,
            "reverse_dns": self.reverse_dns,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "open_ports": self.open_ports,
            "os": self.os
        }

    def __hash__(self) -> int:
        """
        计算 Node 对象的哈希值，基于多个关键属性。用于在集合中唯一标识节点。

        :return: int 哈希值。
        """
        return hash((self.node_id, self.mac_address, self.os, self.vendor))

    def __eq__(self, other: object) -> bool:
        """
        比较两个 Node 对象是否相等，基于其哈希值。

        :param other: object
            另一个对象，通常为 Node 实例。
        :return: bool
            如果两个节点的哈希值相同，则认为它们相等。
        """
        if not isinstance(other, Node):
            return False
        return hash(self) == hash(other)

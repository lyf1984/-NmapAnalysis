class Edge:
    """
    表示网络中的一条边。

    该类用于封装网络中节点之间的连接信息，包括起点、终点、连接类型、使用的协议及网络层级。

    属性:
        - from_node (str): 边的起始节点 ID，通常为 IP 地址。
        - to_node (str): 边的目标节点 ID，通常为 IP 地址。
        - edge_type (str): 边的类型，例如 "traceroute"、"direct"。
        - protocol (str): 边使用的协议，例如 "ICMP"、"TCP"。
        - layer (str): 边所在的网络层，例如 "Layer 3"。

    方法:
        - to_dict(): 将 Edge 对象转换为字典格式，用于 JSON 序列化。
        - __hash__(): 计算 Edge 对象的哈希值，用于在集合中唯一标识边。
        - __eq__(): 比较两个 Edge 对象是否相等。
    """

    def __init__(self, from_node: str, to_node: str, edge_type: str, protocol: str, layer: str):
        """
        初始化 Edge 类实例，表示网络中的一条边（连接两个节点）。

        :param from_node: str
            边的起始节点 ID（通常为 IP 地址）。
        :param to_node: str
            边的目标节点 ID（通常为 IP 地址）。
        :param edge_type: str
            边的类型，例如 "traceroute"、"direct"。
        :param protocol: str
            边使用的协议，例如 "ICMP"、"TCP"。
        :param layer: str
            边所在的网络层，例如 "Layer 3"。
        """
        self.from_node = from_node
        self.to_node = to_node
        self.edge_type = edge_type
        self.protocol = protocol
        self.layer = layer

    def to_dict(self) -> dict:
        """
        将 Edge 对象转换为字典格式，用于 JSON 序列化。

        :return: dict 包含边属性的字典。
        """
        return {
            "from_node": self.from_node,
            "to_node": self.to_node,
            "edge_type": self.edge_type,
            "protocol": self.protocol,
            "layer": self.layer
        }

    def __hash__(self) -> int:
        """
        计算 Edge 对象的哈希值，基于多个关键属性。用于在集合中唯一标识边。

        :return: int 哈希值。
        """
        return hash((self.from_node, self.to_node, self.edge_type, self.protocol, self.layer))

    def __eq__(self, other: object) -> bool:
        """
        比较两个 Edge 对象是否相等，基于其哈希值。

        :param other: object
            另一个对象，通常为 Edge 实例。
        :return: bool
            如果两个边的哈希值相同，则认为它们相等。
        """
        if not isinstance(other, Edge):
            return False
        return hash(self) == hash(other)

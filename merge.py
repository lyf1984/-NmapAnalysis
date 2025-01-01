import json

# 文件路径
current_json_path = 'fscan_results.json'
other_json_path = 'output.json'
output_merged_path = 'merged_results.json'

# 读取当前 JSON 文件
def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

# 合并逻辑
def merge_json(current_data, other_data):
    # 将 "nodes" 从 other_data 中提取
    nodes = other_data.get("nodes", [])

    # 为 current_data 添加节点
    for node in nodes:
        node_ip = node.get("node_id")
        for entry in current_data:
            if entry.get("ip") == node_ip:
                # 合并 open_ports
                current_ports = entry.get("open_ports", [])
                node_ports = [port["port"] for port in node.get("open_ports", [])]
                for port in node_ports:
                    if port not in current_ports:
                        current_ports.append(port)
                entry["open_ports"] = current_ports

                # 合并 os
                if "osinfo" not in entry:
                    entry["osinfo"] = []
                if node.get("os") and node["os"] not in entry["osinfo"]:
                    entry["osinfo"].append(node["os"])

                # 确保其他字段存在
                for field in ["websites", "netbios", "fingerprints", "vulnerabilities"]:
                    if field not in entry:
                        entry[field] = []
                break
        else:
            # 如果节点不存在于 current_data 中，则添加新节点
            current_data.append({
                "ip": node_ip,
                "open_ports": [port["port"] for port in node.get("open_ports", [])],
                "osinfo": [node.get("os")],
                "websites": [],
                "netbios": [],
                "fingerprints": [],
                "vulnerabilities": []
            })
    return current_data

# 加载 JSON 数据
current_data = load_json(current_json_path)
other_data = load_json(other_json_path)

# 合并数据
merged_data = merge_json(current_data, other_data)

# 写入合并后的 JSON 文件
with open(output_merged_path, 'w', encoding='utf-8') as output_file:
    json.dump(merged_data, output_file, indent=4, ensure_ascii=False)

print(f"JSON 文件已成功合并，结果已保存为 {output_merged_path}")

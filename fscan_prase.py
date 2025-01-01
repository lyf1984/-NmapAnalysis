#解析fscan扫描结果的脚本，对应fscan的版本为2.0.0
import json
from collections import defaultdict
import re

# 文件路径
file_path = 'result.txt'
output_path = 'fscan_results.json'

# 按IP分组的结构化数据
results = defaultdict(lambda: {"open_ports": [], "websites": [], "netbios": [], "osinfo": [], "fingerprints": [], "vulnerabilities": []})

# 读取并解析文件
with open(file_path, 'r', encoding='utf-8') as file:
    for line in file:
        line = line.strip()
        if line.startswith("[+] 端口开放"):
            parts = line.split()
            if len(parts) == 3:
                ip_port = parts[2]
                ip, port = ip_port.split(':')
                results[ip]["open_ports"].append(int(port))
        elif line.startswith("[*] 网站标题"):
            match = re.search(r"状态码:(\d+).*长度:(\d+).*标题:(.*?)(重定向地址:|$)", line)
            if match:
                status_code = int(match.group(1))
                length = int(match.group(2))
                title = match.group(3).strip()
                redirect = None
                if "重定向地址:" in line:
                    redirect = line.split("重定向地址:")[-1].strip()
                url = line.split()[2]
                ip = url.split('://')[-1].split(':')[0].split('/')[0]
                website_info = {
                    "url": url,
                    "status_code": status_code,
                    "length": length,
                    "title": title if title != "无标题" else None,
                    "redirect": redirect
                }
                results[ip]["websites"].append(website_info)
        elif line.startswith("[*] NetBios"):
            match = re.search(r"NetBios (\S+)\s+(.*)", line)
            if match:
                ip = match.group(1)
                info = match.group(2).strip()
                results[ip]["netbios"].append(info)
        elif line.startswith("[*] OsInfo"):
            match = re.search(r"OsInfo (\S+)\s+\((.*?)\)", line)
            if match:
                ip = match.group(1)
                os_info = match.group(2).strip()
                results[ip]["osinfo"].append(os_info)
        elif line.startswith("[+] MongoDB") or line.startswith("[+] Memcached") or line.startswith("[+] MySQL") or line.startswith("[+] ftp") or line.startswith("[+] Redis"):
            match = re.search(r"(\S+)\s+(\S+):(\d+)(.*)", line)
            if match:
                service = match.group(1)
                ip = match.group(2)
                port = int(match.group(3))
                details = match.group(4).strip()
                results[ip]["vulnerabilities"].append({"target": f"{ip}:{port}", "type": service, "details": details})
        elif line.startswith("[+] 发现指纹"):
            match = re.search(r"目标:\s+(\S+)\s+指纹:\s+\[(.*?)\]", line)
            if match:
                target = match.group(1)
                fingerprint = match.group(2)
                ip = target.split('://')[-1].split(':')[0]
                results[ip]["fingerprints"].append({"target": target, "fingerprint": fingerprint})
        elif line.startswith("[+] [发现漏洞]"):
            match = re.search(r"目标:\s+(\S+)\s+漏洞类型:\s+(.*?)\s+漏洞名称:\s+(.*?)\s+详细信息:\s+(.*?)$", line)
            if match:
                target = match.group(1)
                vuln_type = match.group(2)
                vuln_name = match.group(3).strip()
                details = match.group(4).strip()
                ip = target.split('://')[-1].split(':')[0]
                results[ip]["vulnerabilities"].append({"target": target, "type": vuln_type, "name": vuln_name, "details": details})
        elif line.startswith("[+] 检测到漏洞"):
            match = re.search(r"检测到漏洞 (\S+) (\S+) 参数:\[(.*?)\]", line)
            if match:
                target = match.group(1)
                vuln_type = match.group(2)
                params = match.group(3).strip()
                ip = target.split('://')[-1].split(':')[0]
                results[ip]["vulnerabilities"].append({"target": target, "type": vuln_type, "params": params})

# 转换为JSON格式
output_data = [
    {
        "ip": ip,
        "open_ports": data["open_ports"],
        "websites": data["websites"],
        "netbios": data["netbios"],
        "osinfo": data["osinfo"],
        "fingerprints": data["fingerprints"],
        "vulnerabilities": data["vulnerabilities"]
    } for ip, data in results.items()
]

# 写入JSON文件
with open(output_path, 'w', encoding='utf-8') as json_file:
    json.dump(output_data, json_file, indent=4, ensure_ascii=False)

print(f"解析完成，结果已保存为 {output_path}")

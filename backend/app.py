#!/usr/bin/env python3
"""
网络拓扑管理系统 - 后端 API 服务
支持通过 SSH 登录交换机并采集 LLDP/SNMP 数据
"""

import json
import ipaddress
import threading
import socket
import time
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import paramiko

app = Flask(__name__)
CORS(app)

# ============================================================
# LLDP 数据采集（通过 SSH）
# ============================================================

def ssh_execute(host, port, username, password, command, timeout=10):
    """通过 SSH 执行命令并返回输出"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        client.close()
        return output, err, None
    except paramiko.AuthenticationException:
        return None, None, "认证失败：用户名或密码错误"
    except paramiko.SSHException as e:
        return None, None, f"SSH 连接异常：{str(e)}"
    except socket.timeout:
        return None, None, "连接超时"
    except Exception as e:
        return None, None, f"连接失败：{str(e)}"


def detect_device_type(output):
    """根据 SSH banner/输出检测设备类型"""
    output_lower = output.lower()
    if 'huawei' in output_lower or 'vrp' in output_lower:
        return 'huawei'
    elif 'cisco' in output_lower or 'ios' in output_lower or 'nx-os' in output_lower:
        return 'cisco'
    elif 'h3c' in output_lower or 'comware' in output_lower:
        return 'h3c'
    elif 'juniper' in output_lower or 'junos' in output_lower:
        return 'juniper'
    elif 'ruijie' in output_lower or '锐捷' in output_lower:
        return 'ruijie'
    else:
        return 'generic'


def get_lldp_commands(device_type):
    """获取对应设备类型的 LLDP 查询命令"""
    commands = {
        'huawei': {
            'lldp_neighbors': 'display lldp neighbor brief',
            'lldp_detail': 'display lldp neighbor',
            'device_info': 'display version',
            'interfaces': 'display interface brief',
            'hostname': 'display current-configuration | include sysname'
        },
        'cisco': {
            'lldp_neighbors': 'show lldp neighbors',
            'lldp_detail': 'show lldp neighbors detail',
            'device_info': 'show version',
            'interfaces': 'show interfaces status',
            'hostname': 'show running-config | include hostname'
        },
        'h3c': {
            'lldp_neighbors': 'display lldp neighbor-information brief',
            'lldp_detail': 'display lldp neighbor-information verbose',
            'device_info': 'display version',
            'interfaces': 'display interface brief',
            'hostname': 'display current-configuration | include sysname'
        },
        'ruijie': {
            'lldp_neighbors': 'show lldp neighbors',
            'lldp_detail': 'show lldp neighbors detail',
            'device_info': 'show version',
            'interfaces': 'show interfaces status',
            'hostname': 'show running-config | include hostname'
        },
        'generic': {
            'lldp_neighbors': 'show lldp neighbors',
            'lldp_detail': 'show lldp neighbors detail',
            'device_info': 'show version',
            'interfaces': 'show interfaces',
            'hostname': 'hostname'
        }
    }
    return commands.get(device_type, commands['generic'])


def parse_huawei_lldp(output):
    """解析华为 LLDP 邻居信息"""
    neighbors = []
    lines = output.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('-') or 'Local' in line or 'Neighbor' in line:
            continue
        # 华为 LLDP brief 格式: LocalInterface  Exptime  Neighbor     NbrPortID
        parts = line.split()
        if len(parts) >= 4:
            neighbors.append({
                'local_port': parts[0],
                'neighbor_device': parts[2] if len(parts) > 2 else 'Unknown',
                'neighbor_port': parts[3] if len(parts) > 3 else 'Unknown',
                'ttl': parts[1] if len(parts) > 1 else '0'
            })
    return neighbors


def parse_cisco_lldp(output):
    """解析 Cisco LLDP 邻居信息"""
    neighbors = []
    lines = output.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('Capability') or line.startswith('Device') or 'capability' in line.lower():
            continue
        parts = line.split()
        if len(parts) >= 5:
            neighbors.append({
                'local_port': parts[1] if len(parts) > 1 else 'Unknown',
                'neighbor_device': parts[0],
                'neighbor_port': parts[2] if len(parts) > 2 else 'Unknown',
                'ttl': '120'
            })
    return neighbors


def parse_generic_lldp(output, device_type):
    """通用 LLDP 解析器"""
    if device_type == 'huawei':
        return parse_huawei_lldp(output)
    elif device_type in ['cisco', 'ruijie']:
        return parse_cisco_lldp(output)
    else:
        return parse_huawei_lldp(output)


def parse_version_info(output, device_type):
    """解析设备版本和型号信息"""
    info = {'model': 'Unknown', 'version': 'Unknown', 'vendor': 'Unknown'}

    if device_type == 'huawei':
        # 华为版本格式
        model_match = re.search(r'Quidway\s+(\S+)|HUAWEI\s+(\S+)|[Ss]\d{4}[A-Z0-9-]*', output)
        if model_match:
            info['model'] = model_match.group(0).strip()
        version_match = re.search(r'VRP.*?V(\S+)', output)
        if version_match:
            info['version'] = 'VRP ' + version_match.group(1)
        info['vendor'] = 'Huawei'

    elif device_type == 'cisco':
        model_match = re.search(r'Cisco\s+(\S+\s+\S+)\s+.*?processor', output, re.IGNORECASE)
        if model_match:
            info['model'] = model_match.group(1)
        version_match = re.search(r'IOS.*?Version\s+(\S+)', output)
        if version_match:
            info['version'] = 'IOS ' + version_match.group(1)
        info['vendor'] = 'Cisco'

    elif device_type == 'h3c':
        model_match = re.search(r'H3C\s+(\S+)', output)
        if model_match:
            info['model'] = 'H3C ' + model_match.group(1)
        info['vendor'] = 'H3C'

    return info


def collect_device_info(host, port, username, password):
    """采集单台设备的完整信息"""
    result = {
        'ip': host,
        'status': 'error',
        'hostname': host,
        'vendor': 'Unknown',
        'model': 'Unknown',
        'version': 'Unknown',
        'device_type': 'generic',
        'neighbors': [],
        'interfaces': [],
        'error': None
    }

    # 先获取设备版本信息用于判断类型
    out, err, error = ssh_execute(host, port, username, password, 'show version 2>/dev/null || display version 2>/dev/null || uname -a')
    if error:
        result['error'] = error
        return result

    device_type = detect_device_type(out or '')
    result['device_type'] = device_type
    cmds = get_lldp_commands(device_type)

    # 获取版本信息
    ver_out, _, _ = ssh_execute(host, port, username, password, cmds['device_info'])
    if ver_out:
        ver_info = parse_version_info(ver_out, device_type)
        result.update(ver_info)

    # 获取主机名
    host_out, _, _ = ssh_execute(host, port, username, password, cmds['hostname'])
    if host_out:
        hostname_match = re.search(r'sysname\s+(\S+)|hostname\s+(\S+)', host_out, re.IGNORECASE)
        if hostname_match:
            result['hostname'] = hostname_match.group(1) or hostname_match.group(2)

    # 获取 LLDP 邻居
    lldp_out, _, _ = ssh_execute(host, port, username, password, cmds['lldp_neighbors'])
    if lldp_out:
        result['neighbors'] = parse_generic_lldp(lldp_out, device_type)

    result['status'] = 'online'
    return result


# ============================================================
# SNMP 数据采集（模拟实现，实际需要 pysnmp）
# ============================================================

def collect_snmp_info(host, community='public', version='2c'):
    """通过 SNMP 采集设备信息"""
    # 标准 SNMP OID
    oids = {
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'ifNumber': '1.3.6.1.2.1.2.1.0',
        # LLDP OIDs
        'lldpRemSysName': '1.0.8802.1.1.2.1.4.1.1.9',
        'lldpRemPortId': '1.0.8802.1.1.2.1.4.1.1.7',
        'lldpLocPortId': '1.0.8802.1.1.2.1.3.7.1.3',
    }

    # 此处为模拟数据，实际部署时使用 pysnmp
    return {
        'snmp_status': 'simulated',
        'oids': oids,
        'note': '实际部署需配置 SNMP community string'
    }


# ============================================================
# API 路由
# ============================================================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'time': time.time()})


@app.route('/api/scan', methods=['POST'])
def scan_network():
    """扫描 IP 范围内的交换机"""
    data = request.get_json()
    ip_range = data.get('ip_range', '')
    port = data.get('port', 22)
    username = data.get('username', '')
    password = data.get('password', '')
    snmp_community = data.get('snmp_community', 'public')
    timeout = data.get('timeout', 5)

    if not ip_range or not username:
        return jsonify({'error': '请提供 IP 范围和 SSH 用户名'}), 400

    # 解析 IP 范围
    hosts = []
    try:
        if '-' in ip_range and '/' not in ip_range:
            # 格式: 192.168.1.1-192.168.1.10
            parts = ip_range.split('-')
            start = ipaddress.ip_address(parts[0].strip())
            end = ipaddress.ip_address(parts[1].strip())
            current = start
            while current <= end:
                hosts.append(str(current))
                current += 1
        elif '/' in ip_range:
            # CIDR 格式: 192.168.1.0/24
            network = ipaddress.ip_network(ip_range.strip(), strict=False)
            hosts = [str(h) for h in network.hosts()]
            if len(hosts) > 256:
                hosts = hosts[:256]  # 限制最多扫描 256 台
        else:
            # 单个 IP 或逗号分隔
            hosts = [h.strip() for h in ip_range.split(',')]
    except ValueError as e:
        return jsonify({'error': f'IP 范围格式错误: {str(e)}'}), 400

    # 先进行端口连通性快速检测
    reachable_hosts = []
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            if result == 0:
                reachable_hosts.append(host)
        except Exception:
            pass

    # 并发采集设备信息
    devices = []
    threads = []
    lock = threading.Lock()

    def collect_and_append(host):
        device_info = collect_device_info(host, int(port), username, password)
        snmp_info = collect_snmp_info(host, snmp_community)
        device_info['snmp'] = snmp_info
        with lock:
            devices.append(device_info)

    # 最多并发 20 线程
    max_threads = min(20, len(reachable_hosts))
    semaphore = threading.Semaphore(max_threads)

    def collect_with_semaphore(host):
        with semaphore:
            collect_and_append(host)

    for host in reachable_hosts:
        t = threading.Thread(target=collect_with_semaphore, args=(host,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=30)

    # 构建拓扑数据
    topology = build_topology(devices)

    return jsonify({
        'total_scanned': len(hosts),
        'reachable': len(reachable_hosts),
        'devices': devices,
        'topology': topology
    })


@app.route('/api/device/detail', methods=['POST'])
def device_detail():
    """获取单台设备详细信息"""
    data = request.get_json()
    host = data.get('ip')
    port = data.get('port', 22)
    username = data.get('username')
    password = data.get('password')

    if not all([host, username, password]):
        return jsonify({'error': '参数不完整'}), 400

    device_info = collect_device_info(host, port, username, password)
    snmp_info = collect_snmp_info(host)
    device_info['snmp'] = snmp_info

    return jsonify(device_info)


@app.route('/api/topology/demo', methods=['GET'])
def demo_topology():
    """返回演示拓扑数据（用于前端展示测试）"""
    devices = [
        {
            'ip': '10.0.0.1',
            'hostname': 'Core-SW-01',
            'vendor': 'Huawei',
            'model': 'S5735-L24T4X',
            'version': 'VRP V200R022',
            'device_type': 'huawei',
            'status': 'online',
            'role': 'core',
            'neighbors': [
                {'local_port': 'GE0/0/1', 'neighbor_device': 'Access-SW-01', 'neighbor_port': 'GE0/0/24', 'link_type': '1G Ethernet'},
                {'local_port': 'GE0/0/2', 'neighbor_device': 'Access-SW-02', 'neighbor_port': 'GE0/0/24', 'link_type': '1G Ethernet'},
                {'local_port': 'GE0/0/3', 'neighbor_device': 'Access-SW-03', 'neighbor_port': 'GE0/0/24', 'link_type': '1G Ethernet'},
                {'local_port': '10GE0/0/1', 'neighbor_device': 'Core-SW-02', 'neighbor_port': '10GE0/0/1', 'link_type': '10G Ethernet'},
            ]
        },
        {
            'ip': '10.0.0.2',
            'hostname': 'Core-SW-02',
            'vendor': 'Huawei',
            'model': 'S5735-L24T4X',
            'version': 'VRP V200R022',
            'device_type': 'huawei',
            'status': 'online',
            'role': 'core',
            'neighbors': [
                {'local_port': 'GE0/0/1', 'neighbor_device': 'Access-SW-04', 'neighbor_port': 'GE0/0/24', 'link_type': '1G Ethernet'},
                {'local_port': 'GE0/0/2', 'neighbor_device': 'Access-SW-05', 'neighbor_port': 'GE0/0/24', 'link_type': '1G Ethernet'},
                {'local_port': '10GE0/0/1', 'neighbor_device': 'Core-SW-01', 'neighbor_port': '10GE0/0/1', 'link_type': '10G Ethernet'},
            ]
        },
        {
            'ip': '10.0.1.1',
            'hostname': 'Access-SW-01',
            'vendor': 'Cisco',
            'model': 'Catalyst 2960X-24TS',
            'version': 'IOS 15.2(7)E6',
            'device_type': 'cisco',
            'status': 'online',
            'role': 'access',
            'neighbors': [
                {'local_port': 'GE0/24', 'neighbor_device': 'Core-SW-01', 'neighbor_port': 'GE0/0/1', 'link_type': '1G Ethernet'},
            ]
        },
        {
            'ip': '10.0.1.2',
            'hostname': 'Access-SW-02',
            'vendor': 'Cisco',
            'model': 'Catalyst 2960X-24TS',
            'version': 'IOS 15.2(7)E6',
            'device_type': 'cisco',
            'status': 'online',
            'role': 'access',
            'neighbors': [
                {'local_port': 'GE0/24', 'neighbor_device': 'Core-SW-01', 'neighbor_port': 'GE0/0/2', 'link_type': '1G Ethernet'},
            ]
        },
        {
            'ip': '10.0.1.3',
            'hostname': 'Access-SW-03',
            'vendor': 'H3C',
            'model': 'S5500V3-28P-EI',
            'version': 'Comware 7.1.070',
            'device_type': 'h3c',
            'status': 'online',
            'role': 'access',
            'neighbors': [
                {'local_port': 'GE1/0/24', 'neighbor_device': 'Core-SW-01', 'neighbor_port': 'GE0/0/3', 'link_type': '1G Ethernet'},
            ]
        },
        {
            'ip': '10.0.1.4',
            'hostname': 'Access-SW-04',
            'vendor': 'Ruijie',
            'model': 'RG-S2928G-E',
            'version': 'RGOS 11.4',
            'device_type': 'ruijie',
            'status': 'online',
            'role': 'access',
            'neighbors': [
                {'local_port': 'GE0/24', 'neighbor_device': 'Core-SW-02', 'neighbor_port': 'GE0/0/1', 'link_type': '1G Ethernet'},
            ]
        },
        {
            'ip': '10.0.1.5',
            'hostname': 'Access-SW-05',
            'vendor': 'Huawei',
            'model': 'S2720-28TP-EI',
            'version': 'VRP V200R019',
            'device_type': 'huawei',
            'status': 'online',
            'role': 'access',
            'neighbors': [
                {'local_port': 'GE0/0/24', 'neighbor_device': 'Core-SW-02', 'neighbor_port': 'GE0/0/2', 'link_type': '1G Ethernet'},
            ]
        },
    ]

    topology = build_topology(devices)
    return jsonify({
        'total_scanned': 7,
        'reachable': 7,
        'devices': devices,
        'topology': topology
    })


def build_topology(devices):
    """从设备信息构建拓扑图数据"""
    nodes = []
    links = []
    seen_links = set()  # 防止重复链路

    device_map = {d['hostname']: d for d in devices}
    ip_hostname_map = {d['ip']: d['hostname'] for d in devices}

    for device in devices:
        nodes.append({
            'id': device['hostname'],
            'ip': device['ip'],
            'hostname': device['hostname'],
            'vendor': device.get('vendor', 'Unknown'),
            'model': device.get('model', 'Unknown'),
            'version': device.get('version', 'Unknown'),
            'device_type': device.get('device_type', 'generic'),
            'role': device.get('role', 'access'),
            'status': device.get('status', 'unknown')
        })

        for neighbor in device.get('neighbors', []):
            neighbor_id = neighbor.get('neighbor_device', '')
            if not neighbor_id:
                continue

            # 创建链路唯一标识
            link_key = tuple(sorted([device['hostname'], neighbor_id]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                # 判断链路类型
                local_port = neighbor.get('local_port', '')
                link_type = determine_link_type(local_port, neighbor.get('link_type', ''))

                links.append({
                    'source': device['hostname'],
                    'target': neighbor_id,
                    'source_port': local_port,
                    'target_port': neighbor.get('neighbor_port', ''),
                    'link_type': link_type,
                    'speed': get_link_speed(local_port)
                })

    return {'nodes': nodes, 'links': links}


def determine_link_type(port_name, hint=''):
    """根据端口名称判断链路类型"""
    if hint and hint != '':
        return hint
    port_lower = port_name.lower()
    if '10ge' in port_lower or 'xge' in port_lower or 'te' in port_lower:
        return '10G Ethernet'
    elif '25ge' in port_lower:
        return '25G Ethernet'
    elif '40ge' in port_lower or 'fo' in port_lower:
        return '40G Ethernet'
    elif '100ge' in port_lower or 'hu' in port_lower:
        return '100G Ethernet'
    elif 'ge' in port_lower or 'gi' in port_lower or 'fa' in port_lower:
        return '1G Ethernet'
    elif 'lag' in port_lower or 'po' in port_lower or 'agg' in port_lower:
        return 'LAG/聚合链路'
    else:
        return '1G Ethernet'


def get_link_speed(port_name):
    """获取链路速率"""
    port_lower = port_name.lower()
    if '100ge' in port_lower:
        return '100G'
    elif '40ge' in port_lower:
        return '40G'
    elif '25ge' in port_lower:
        return '25G'
    elif '10ge' in port_lower or 'xge' in port_lower or 'te' in port_lower:
        return '10G'
    else:
        return '1G'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

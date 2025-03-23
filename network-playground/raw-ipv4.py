#!/usr/bin/env python3
# Description:
# * 通过原始套接字发送IPv4数据包来测试eBPF程序。
# * 将持续以100Hz的频率发送直到人工中断。
# Usage: sudo python3 raw-ipv4.py

import socket
import random
import struct
import time

# 随机生成负载
# 16字节数据。假设传感器传输两个u64。
u64_1 = random.getrandbits(64)
u64_2 = random.getrandbits(64)
data = struct.pack('!QQ', u64_1, u64_2)  # 使用struct打包两个64位无符号整数

# IP头部
ip_header = struct.pack(
    '!BBHHHBBH4s4s',
    0x45,  # 版本(4)和头部长度(5) -> 0x45
    104,  # 服务类型，用于区分其他数据包。ebpf程序将检测该类型数据包。
    20 + len(data),  # 总长度：IP头部+数据
    random.randint(0, 65535),  # 标识符（随机）
    0,  # 标志和片偏移
    64,  # 生存时间
    253,  # 用于实验和测试的协议编号
    0,  # 校验和，稍后填充
    socket.inet_aton('127.0.0.1'), # 源IP
    socket.inet_aton('127.0.0.1')  # 目标IP
)

# 计算IP头部的校验和
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# 计算最终IP头部（仅需一次）
final_ip_header = ip_header[:10] + struct.pack('!H', checksum(ip_header)) + ip_header[12:]

# 仅创建一次套接字
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# 预组合完整数据包
packet = final_ip_header + data

# 发送循环
destination_ip = '127.0.0.1'
try:
    while True:
        s.sendto(packet, (destination_ip, 0))
        time.sleep(0.01)  # 100Hz发送频率
except KeyboardInterrupt:
    print("发送停止")
finally:
    s.close()
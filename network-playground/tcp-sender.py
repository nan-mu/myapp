#!/usr/bin/env python3
# filepath: /home/nan/myapp/network-playground/tcp-sender.py
import socket
import struct
import os
import argparse
from fcntl import ioctl

# 常量定义
SIOCGIFMTU = 0x8921  # 获取MTU的ioctl指令

# 获取指定网卡的MTU值
def get_mtu(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('<16sH', ifname.encode(), 0) + b'\x00' * 14
    try:
        ifs = ioctl(s, SIOCGIFMTU, ifr)
        mtu = struct.unpack('<H', ifs[16:18])[0]
    finally:
        s.close()
    return mtu

# 发送带有特定TOS值的TCP数据
def send_max_tcp(ifname, dest_ip, dest_port=12345, tos_value=0x68):  # 0x68 = 0b01101000
    mtu = get_mtu(ifname)
    payload_size = mtu - 40  # 减去IP头(20字节)和TCP头(20字节)
    random_data = os.urandom(payload_size)

    # 创建TCP套接字
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 绑定到指定网卡 (需要root权限)
    s.setsockopt(socket.SOL_SOCKET, 25, ifname.encode())  # SO_BINDTODEVICE=25
    
    # 设置IP TOS字段 - 这是关键修改
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos_value)
    print(f"IP TOS字段设置为: 0x{tos_value:02x} (二进制: {tos_value:08b})")
    
    try:
        # 建立TCP连接
        s.connect((dest_ip, dest_port))
        print(f"已连接到 {dest_ip}:{dest_port}，准备发送 {payload_size} 字节数据")

        # 发送数据
        s.sendall(random_data)
        print(f"已发送 {payload_size} 字节数据")
    except Exception as e:
        print(f"发送失败: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="发送带特定TOS字段的TCP数据")
    parser.add_argument("--ifname", default="eth4", help="网卡名称 (默认: eth4)")
    parser.add_argument("--ip", default="192.168.1.96", help="目标IP地址 (默认: 192.168.1.96)")
    parser.add_argument("--port", type=int, default=12345, help="目标端口 (默认: 12345)")
    parser.add_argument("--tos", type=lambda x: int(x, 0), default=0x68, 
                        help="TOS值，可以是十进制、十六进制(0x68)或二进制(0b01101000) (默认: 0x68)")
    
    args = parser.parse_args()
    send_max_tcp(args.ifname, args.ip, args.port, args.tos)
#!/usr/bin/env python3
import socket
import argparse

def send_max_tcp(ifname, ip, port, tos, size):
    try:
        # 创建 TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 设置 TOS 字段 (需要 root 权限)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
        
        # 绑定到指定网卡 (可选)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        
        # 建立 TCP 连接
        sock.connect((ip, port))
        
        # 生成并发送指定大小的数据
        data = b'A' * size
        sock.send(data)
        
        print(f"已发送 {size} 字节数据到 {ip}:{port}，TOS=0x{tos:02x}")
        
    except Exception as e:
        print(f"发生错误: {str(e)}")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="发送带特定TOS字段的TCP数据")
    parser.add_argument("--ifname", default="eth0", help="网卡名称 (默认: eth0)")
    parser.add_argument("--ip", default="192.168.1.79", help="目标IP地址 (默认: 192.168.1.79)")
    parser.add_argument("--port", type=int, default=12345, help="目标端口 (默认: 12345)")
    parser.add_argument("--tos", type=lambda x: int(x, 0), default=0x6c, 
                       help="TOS值，可以是十进制、十六进制(0x6c)或二进制(0b01101000) (默认: 0x6c)")
    parser.add_argument("--size", type=int, default=1200, help="发送的数据大小(字节) (默认: 1200)")
    
    args = parser.parse_args()
    send_max_tcp(args.ifname, args.ip, args.port, args.tos, args.size)

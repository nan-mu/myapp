import socket
import struct
import os
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

# 发送最大不分片的TCP数据
def send_max_tcp(ifname, dest_ip, dest_port=12345):
    mtu = get_mtu(ifname)
    payload_size = mtu - 40  # 减去IP头(20字节)和TCP头(20字节)
    random_data = os.urandom(payload_size)

    # 创建TCP套接字
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 绑定到指定网卡 (需要root权限)
    s.setsockopt(socket.SOL_SOCKET, 25, ifname.encode())  # SO_BINDTODEVICE=25
    
    try:
        # 建立TCP连接
        s.connect((dest_ip, dest_port))
        print(f"已连接到 {dest_ip}:{dest_port}，准备发送 {payload_size} 字节数据")

        # 发送数据
        s.sendall(random_data)
        print(f"已发送 {payload_size} 字节数据到 {ifname}")
    finally:
        s.close()

# 示例使用
if __name__ == "__main__":
    # 替换为你的网卡名称、目标IP和端口
    send_max_tcp("eth0", "192.168.1.100", 12345)

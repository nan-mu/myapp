#!/usr/bin/env python3
# filepath: /home/nan/myapp/network-playground/tcp_receiver.py
import socket
import time
import argparse
from datetime import datetime

def tcp_server(host='0.0.0.0', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x6c)
    
    # 必须设置 SO_REUSEADDR
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.bind((host, port))
    server_socket.listen(5)
    # 后续代码保持不变...

    print(f"[{datetime.now()}] TCP服务器启动，监听 {host}:{port}")
    
    try:
        while True:
            # 接受客户端连接
            client_socket, client_address = server_socket.accept()
            print(f"[{datetime.now()}] 接收到来自 {client_address} 的连接")
            
            # 接收数据
            start_time = time.time()
            total_bytes = 0
            buffer_size = 4096  # 接收缓冲区大小
            
            try:
                while True:
                    data = client_socket.recv(buffer_size)
                    if not data:
                        break
                    total_bytes += len(data)
                    print(f"\r已接收: {total_bytes} 字节", end="", flush=True)
            except Exception as e:
                print(f"\n接收数据时出错: {e}")
            finally:
                # 关闭客户端连接
                client_socket.close()
            
            # 计算接收速率
            elapsed_time = time.time() - start_time
            rate = total_bytes / (1024 * elapsed_time) if elapsed_time > 0 else 0
            
            print(f"\n[{datetime.now()}] 接收完成:")
            print(f"- 总接收字节: {total_bytes} 字节")
            print(f"- 耗时: {elapsed_time:.4f} 秒")
            print(f"- 速率: {rate:.2f} KB/s")
            
    except KeyboardInterrupt:
        print("\n服务器关闭")
    finally:
        server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP数据接收服务器")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="监听端口 (默认: 12345)")
    
    args = parser.parse_args()
    tcp_server(args.host, args.port)
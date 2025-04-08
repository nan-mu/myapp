#!/usr/bin/env python3

import struct

# 计算IP头部的校验和
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# 通过差异增量计算新的校验和
def update_checksum(old_checksum, old_word, new_word):
    """根据变化字段计算新的IP校验和"""
    # 计算增量: 从旧校验和中减去旧值，加上新值
    checksum = (~old_checksum & 0xFFFF)  # 校验和取反得到和
    checksum = checksum - old_word + new_word  # 更新和
    
    # 处理进位
    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
    return ~checksum & 0xFFFF  # 再次取反得到新校验和


# 抓包得到的IP头部
# 0x0000:  4510 00e4 6a90 4000 4006 4b66 c0a8 015d  E...j.@.@.Kf...]
# 0x0010:  c0a8 0160


# 直接使用抓包中的十六进制数据
# ip_header_hex = "4510 00e4 6a90 4000 4006 0000 c0a8 015d c0a8 0160"
# 0x6845, 0x3c00, 0x29d8, 0x0040, 0x0640,
#         0x1cde, 0xa8c0, 0x6001, 0xa8c0, 0x5d01,
ip_header_hex = "4568 003c d829 4000 4006 0000 c0a8 0160 c0a8 015d"
ip_header_hex = ip_header_hex.replace(" ", "")
ip_header_bytes = bytes.fromhex(ip_header_hex)
old_checksum = checksum(ip_header_bytes)
print(f"checksum: {old_checksum:04x}")

ip_header_new = "4568 003c d829 4000 4006 0000 c0a8 0160 c0a8 014f"
ip_header_new = ip_header_new.replace(" ", "")
ip_header_bytes = bytes.fromhex(ip_header_new)

print(f"new checksum: {checksum(ip_header_bytes):04x}")

# 差分计算校验和
old_word = 0x015d
new_word = 0x014f
new_checksum = update_checksum(old_checksum, old_word, new_word)
print(f"增量计算新校验和: 0x{new_checksum:04x}")

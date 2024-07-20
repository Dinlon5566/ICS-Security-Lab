#!/usr/bin/python

############################################
# 使用 Socket 發送手動輸入的 Modbus TCP Payloads
# 需 sudo 權限
# Author: @dinlon5566 2024/06/27
############################################
import socket
from time import sleep

def build_modbus_packet(modbus_hex_payload):

    return bytes.fromhex(modbus_hex_payload)

def send_modbus_payloads(cmd_list, target_ip="192.168.1.5", target_port=502,delay=0.2,replay=1 ):
    """
    使用一個 TCP 連線發送多個 Modbus TCP 負載到指定的目標 IP 和端口。
    :param cmd_list: 包含多個 Modbus 負載的十六進制字串列表
    :param target_ip: 目標 IP 地址
    :param target_port: 目標端口
    """
    cmdId = 0
    # 建立 socket 連線
    for i in range(replay):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            for modbus_hex_payload in cmd_list:
                cmdId = cmdId + 1
                print("cmd ID:", cmdId)
                modbus_packet = build_modbus_packet(modbus_hex_payload)
                
                print("Sent:", modbus_hex_payload)
                s.send(modbus_packet)

                response = s.recv(1024)  
                print("Received:", response)
                
                sleep(delay)
while True:
    cmd = []
    cmd.append(input("Enter the command: "))
    send_modbus_payloads(cmd)
    
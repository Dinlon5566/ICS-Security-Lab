#!/usr/bin/python
import socket
from time import sleep

def build_modbus_packet(modbus_hex_payload):

    return bytes.fromhex(modbus_hex_payload)

def send_modbus_payloads(cmd_list, target_ip="192.168.1.5", target_port=502, delay=0.2, replay=1):
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


cmd = ["6dca0000000e01420300090000006400010001ff",
       "6dca0000000e0142030009000000640001000100"]

cmd_all_on = [
    "07520000000e01420300090000025e00010001ff",  # 學校左
    "078e0000000e01420300090000026200010001ff",  # 學校右
    "c7dd0000000e01420300090000026300010001ff",  # rolad&park
    "d1350000000e01420300090000026500010001ff",  # 住宅左
    "3ddf0000000e01420300090000a01600010001ff",  # 商辦區右
    "37110000000e01420300090000026700010001ff",  # 商辦區左
    "317f0000000e01420300090000026600010001ff",  # 停車場右
    "2aa30000000e01420300090000026000010001ff",  # 停車場左
]

# "d32e0000000e01420300090000a01500010001ff",  # 住宅右(常閉)

cmd_all_off = [
    "07520000000e01420300090000025e0001000100",  # 學校左
    "078e0000000e0142030009000002620001000100",  # 學校右
    "c7dd0000000e0142030009000002630001000100",  # rolad&park
    "d1350000000e0142030009000002650001000100",  # 住宅左
    "37110000000e0142030009000002670001000100",  # 商辦區左
    "3ddf0000000e01420300090000a0160001000100",  # 商辦區右
    "2aa30000000e0142030009000002600001000100",  # 停車場左
    "317f0000000e0142030009000002660001000100",  # 停車場右
]

while True:
    send_modbus_payloads(cmd_all_on)
    sleep(0.5)
    send_modbus_payloads(cmd_all_off)

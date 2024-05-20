import ipcalc
import socket
import random
import re
import threading
import configparser
import os

# ANSI color codes for terminal output
G = '\033[32m'
O = '\033[33m'
GR = '\033[37m'
R = '\033[31m'

print(O + '''
\tWEBSOCKET SCANNER
\tBy : ABDOXFOX
\t  version Faster (using threading)
''' + GR)

def cidrs():
    cidrslist = []
    try:
        with open('ipv4.txt') as file:
            for cidr in file.readlines():
                cidrslist.append(cidr.strip('\n'))
    except FileNotFoundError:
        print(f"{R}[ERROR] 'ipv4.txt' file not found!{GR}")
        sys.exit(1)
    return cidrslist

def save(x):
    with open('wrCloudflrIp.txt', 'a') as fl:
        fl.write(str(x) + '\n')

def scanner(host):
    sock = socket.socket()
    sock.settimeout(5)
    try:
        sock.connect((str(host), 80))
        payload = 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(host)
        sock.send(payload.encode())
        response = sock.recv(1024).decode('utf-8', 'ignore')
        for data in response.split('\r\n'):
            data = data.split(':')
            if re.match(r'HTTP/\d(\.\d)?', data[0]):
                print('response status from {}: {}{}{}'.format(host, O, data[0], GR))
            if data[0] == 'Server':
                try:
                    if data[1].strip() == 'cloudflare':
                        print('{}server: {} | Found working: {}{}'.format(G, host, host, GR))
                        save(f'{host} === opened')
                        payloadsnd(host)
                except Exception as e:
                    print(f"{R}[ERROR] {e}{GR}")
    except Exception as e:
        print(f"{R}[ERROR] {e}{GR}")
    finally:
        sock.close()

def auto_replace(server, ip):
    try:
        packet = server.recv(1024).decode('utf-8', 'ignore')
        status = packet.split('\n')[0]
        if re.match(r'HTTP/\d(\.\d)? 101', status):
            print(f'{O}[TCP] response from {ip}: {G}{status}{GR}')
            save(f'{ip} response ==== {status}')
        else:
            if re.match(r'HTTP/\d(\.\d)? \d\d\d ', status):
                server.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
                print(f'{O}[TCP] response from {ip}: {R}{status}{GR}')
                return auto_replace(server, ip)
    except Exception as e:
        print(f"{R}[ERROR] {e}{GR}")

def payloadsnd(ip):
    config = configparser.ConfigParser()
    try:
        config.read_file(open('configfile.ini'))
    except FileNotFoundError:
        print(f"{R}[ERROR] 'configfile.ini' file not found!{GR}")
        return

    domain = config['websocket'].get('custom_domain', '')
    if not domain:
        print(f"{R}[ERROR] 'custom_domain' not found in configuration!{GR}")
        return

    port = 80
    try:
        sc = socket.socket()
        sc.connect((str(ip), port))
        payload = f'GET / HTTP/1.0[crlf]Host: {domain}[crlf][crlf]'
        payload = payload.replace('[crlf]', '\r\n')
        sc.send(payload.encode())
        auto_replace(sc, ip)
    except Exception as e:
        print(f"{R}[ERROR] {e}{GR}")
    finally:
        sc.close()

def Main():
    ipdict = {}
    ranges = cidrs()
    for k, v in enumerate(ranges):
        ipdict[k] = v
    iprange = []
    for choose in range(len(ipdict)):
        cidr = ipdict[choose]
        for ip in ipcalc.Network(cidr):
            iprange.append(ip)
    for index in range(len(iprange)):
        try:
            print("{}[INFO] Probing... ({}/{}) [{}]{}".format(
                R, index + 1, len(iprange), iprange[index], GR))
            sc = threading.Thread(target=scanner, args=(iprange[index],))
            sc.start()
        except KeyboardInterrupt:
            print('{}Scan aborted by user!{}'.format(R, GR))
            break

if __name__ == "__main__":
    Main()
		 

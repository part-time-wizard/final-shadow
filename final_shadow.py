print("! Cisco IOS XE Software Hardening Guide")
print("! Version 0.0.001")
print("================================")

# No Service Password-Recovery
print("no service password-recovery")

# Disable Unused Services
print("no service tcp-small-servers")
print("no service udp-small-servers")
print("no ip finger")
print("ip dhcp bootp ignore")
print("no mop enabled")
print("no ip domain-lookup")
print("no service pad")
print("no ip http server")
print("no ip http secure-server")
print("no service config")
print("no cdp run")
print("no lldp run")
print("no sdflash")
print("no guestshell")
print("no vstack")

# EXEC Timeout
print("line con 0")
print(" exec-timeout 5 0")
print("line vty 0 4")
print(" exec-timeout 5 0")

# Keepalive for TCP Sessions
print("ip tcp keepalive-in")
print("ip tcp keepalive-out")

# Management Interface Use
print("interface Loopback0")
print("ip address <management_ip_address> <subnet_mask>")
#  To-Do: Add source interface for management protocols

# Memory Threshold Notifications
print("memory free low-watermark processor <threshold_value>")
print("memory free low-watermark io <threshold_value>")
print("memory reserve critical <threshold_value>")

# CPU Thresholding Notification
print("snmp-server enable traps cpu threshold")
print("snmp-server host <host-address> <community-string> cpu")
print("rocess cpu threshold type <type> rising <percentage> interval <seconds> [falling <percentage> interval <seconds>]")
print("process cpu statistics limit entry-percentage <number> [size <seconds>]")
#  To-Do: Replace placeholders with actual values by device type


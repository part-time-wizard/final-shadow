print("! Cisco IOS XE Software Hardening Guide")
print("! Version 0.0.001")
print("!================================")

# General Management Plane Hardening
# |-- No Service Password-Recovery
print("no service password-recovery")

# |-- Disable Unused Services
print("no service tcp-small-servers")
print("no service udp-small-servers")
print("no ip finger")
print("ip dhcp bootp ignore")
#  To-Do: Need to confirm MOP is enabled on interfaces `Router#show subsys | include mop`
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

# |-- EXEC Timeout
print("line con 0")
print(" exec-timeout 5 0")
print("line vty 0 4")
print(" exec-timeout 5 0")

# |-- Keepalive for TCP Sessions
print("ip tcp keepalive-in")
print("ip tcp keepalive-out")

# |-- Management Interface Use
print("interface Loopback0")
print("!ip address <management_ip_address> <subnet_mask>")
print('ntp source Loopback0')

#  To-Do: Add source interface for management protocols
#  To-Do: Need to add default route via management interface with VRF
#  To-Do: Need to determine layer-2 vs. layer-3 management interface configuration

# |-- Memory Threshold Notifications
print("!memory free low-watermark processor <threshold_value>")
print("!memory free low-watermark io <threshold_value>")
print("!memory reserve critical <threshold_value>")

# |-- CPU Thresholding Notification
print("snmp-server enable traps cpu threshold")
print("!snmp-server host <host-address> <community-string> cpu")
print("!process cpu threshold type <type> rising <percentage> interval <seconds> [falling <percentage> interval <seconds>]")
print("!process cpu statistics limit entry-percentage <number> [size <seconds>]")
#  To-Do: Replace placeholders with actual values by device type

# \-- Network Time Protocol
print("ntp authenticate")
print("!ntp authentication-key <key_number #1> md5 <key_string #1>")
print("!ntp authentication-key <key_number #2> md5 <key_string #2>")
print("!ntp trusted-key <key_number #1>")
print("!ntp trusted-key <key_number #2>")
print("!ntp server <ntp_server_ip_address> key <key_number #1>")
print("!ntp server <ntp_server_ip_address> key <key_number #2>")
#  To-Do: Need to replace placeholders with actual values, determine if both keys are the same

#  Limit Access to the Network with Infrastructure ACLs

#  To-Do: Add Infrastructure ACLs for every interface with an IP address, Mgmt, Loopback, SVI, etc.

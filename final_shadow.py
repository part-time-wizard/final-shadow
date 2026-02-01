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
print("no ip domain lookup")
print("no service pad")
print("no ip http server")
print("no ip http secure-server")
print("no service config")
print("no cdp run")
print("no lldp run")  #Hidden command `show run all | inc lldp` to see command

#  Note: The Cisco C9300, C9400, and C9500 do not have SD Flash slots.
#  print("!no sdflash")

#  Note: Command does not work in CML, need to try `guestshell disable` and/or `no iox`
print("no guestshell")

#  Note: vStack is the Smart Install (SMI) feature, uses TCP port 4786
print("no vstack")
print("no vstack config")  # Additional command to ensure there is no vStack Config

# |-- EXEC Timeout
print("line con 0")
print(" exec-timeout 5 0")
print("line vty 0 4")
print(" exec-timeout 5 0")

# |-- Keepalive for TCP Sessions
print("service tcp-keepalives-in")
print("service tcp-keepalives-out")

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

# Limit Access to the Network with Infrastructure ACLs

'''
ip access-list extended ACL-INFRASTRUCTURE-IN
--- Permit required connections for routing protocols and network management
permit tcp host <trusted-ebgp-peer> host <local-ebgp-address> eq 179
permit tcp host <trusted-ebgp-peer> eq 179 host <local-ebgp-address>
permit tcp host <trusted-management-stations> any eq 22
permit udp host <trusted-netmgmt-servers> any eq 161
--- Deny all other IP traffic to any network device
deny ip any <infrastructure-address-space> <wildcard-mask>
--- Permit transit traffic
permit ip any any
'''

#  To-Do: Multiple sections of the Hardening Guide need to write to the same ACL.
#  To-Do: Add Infrastructure ACLs for every interface with an IP address, Mgmt, Loopback, SVI, etc.

# |-- ICMP Packet Filtering

'''
ip access-list extended ACL-INFRASTRUCTURE-IN
--- Permit ICMP Echo (ping) from trusted management stations and servers
permit icmp host <trusted-management-stations> any echo
permit icmp host <trusted-netmgmt-servers> any echo
--- Deny all other IP traffic to any network device
deny ip any <infrastructure-address-space> <wildcard-mask>
--- Permit transit traffic
permit ip any any
'''

#  To-Do: Add ICMP filtering to Infrastructure ACLs for every interface with an IP address, Mgmt, Loopback, SVI, etc.
#  To-Do: Need to replace placeholders with actual values

# |-- Filter IP Fragments

'''
ip access-list extended ACL-INFRASTRUCTURE-IN
--- Deny IP fragments that use protocol-specific ACEs to aid in
--- classification of attack traffic
deny tcp any any fragments
deny udp any any fragments
deny icmp any any fragments
deny ip any any fragments
--- Deny all other IP traffic to any network device
deny ip any <infrastructure-address-space> <wildcard-mask>
--- Permit transit traffic
permit ip any any
'''

#  To-Do: Add IP fragment filtering to Infrastructure ACLs for every interface with an IP address, Mgmt, Loopback, SVI, etc.
#  To-Do: Need to replace placeholders with actual values
#  To-Do: Need to confirm fragment filtering does not impact legitimate traffic
#  To-Do: Fragment filtering needs to be first in the ACL to be effective

#  |-- ACL Support for Filtering IP Options

'''
ip access-list extended ACL-INFRASTRUCTURE-IN
--- Deny IP packets that contain IP options
deny ip any any option any-options
--- Deny all other IP traffic to any network device
deny ip any <infrastructure-address-space> <wildcard-mask>
--- Permit transit traffic
permit ip any any
''' 
#  To-Do: Add IP options filtering to Infrastructure ACLs for every interface with an IP address, Mgmt, Loopback, SVI, etc.
#  To-Do: Need to replace placeholders with actual values
#  To-Do: Need to confirm IP options filtering does not impact legitimate traffic
#  To-Do: IP options filtering needs to be first in the ACL to be effective

# \-- ACL Support to Filter on TTL Value

'''
ip access-list extended ACL-INFRASTRUCTURE-IN
--- Deny IP packets with TTL values insufficient to traverse the network
deny ip any any ttl lt 6
--- Deny all other IP traffic to any network device
deny ip any <infrastructure-address-space> <mask>
--- Permit transit traffic
permit ip any any
'''

# Secure Interactive Management Sessions
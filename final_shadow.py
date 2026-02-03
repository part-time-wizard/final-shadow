print("! Cisco IOS XE Software Hardening Guide")
print("! Version 0.0.001")
print("!================================")

# General Management Plane Hardening
# |-- No Service Password-Recovery
# print("no service password-recovery"). # Deterimine if this is desired in your environment

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
# |-- Management Plane Protection
print("control-plane host")
print("management-interface Loopback0 allow ssh https")

# |-- Control Plane Protection

'''
See the Control Plan Policing Guide for full configuration details.
Add link to CCP Guide here.
'''

# |-- Encrypt Management Sessions
# This is a configuration example for SSH services:
print("ip domain-name example.com")
print("crypto key generate rsa modulus 2048")
print("ip ssh time-out 60")
print("ip ssh authentication-retries 3")
print("ip ssh source-interface GigabitEthernet 0/1")
print("line vty 0 4")
print("transport input ssh")
# This configuration example enables SCP services:
print("ip scp server enable")
# This is a configuration example for HTTPS services:
print("crypto key generate rsa modulus 2048")
print("ip http secure-server")

# |-- SSHv2
print("hostname router")
print("ip domain-name example.com")
print("crypto key generate rsa modulus 2048")
print("ip ssh time-out 60")
print("ip ssh authentication-retries 3")
print("ip ssh source-interface GigabitEthernet 0/1")
print("ip ssh version 2")
print("line vty 0 4")
print("transport input ssh")

# |-- SSHv2 Enhancements for RSA Keys

#Configure a hostname for the device.
print("hostname router")
#Configure a domain name.
print("ip domain name cisco.com")
#Generate RSA key pairs that use a modulus of 2048 bits.
print("crypto key generate rsa modulus 2048")
#Configure SSH-RSA keys for user and server authentication on the SSH server.
print("ip ssh pubkey-chain")
#Configure the SSH username.
#Configure SSH-RSA keys for user and server authentication on the SSH server.
print("ip ssh pubkey-chain")
#Configure the SSH username.
print("username ssh-user")
#Specify the RSA public key of the remote peer.
#You must then configure either the key-string command
#(followed by the RSA public key of the remote peer) or the
#key-hash command (followed by the SSH key type and version).
'''
Refer to Configuring the Cisco IOS XE SSH Server to Perform RSA-Based User Authentication for more information on the use of RSA keys with SSHv2.
This example configuration enables the Cisco IOS XE SSH client to perform RSA-based server authentication.
'''
print("hostname router")
print("ip domain-name cisco.com")
#Generate RSA key pairs.
print("crypto key generate rsa")
#Configure SSH-RSA keys for user and server authentication on the SSH server.
print("ip ssh pubkey-chain")
#Enable the SSH server for public-key authentication on the router.
print("server SSH-server-name")
#Specify the RSA public-key of the remote peer.
#You must then configure either the key-string command  (followed by the RSA public key of the remote peer) or thea
print("key-hash <key-type> <key-name>") #command (followed by the SSH key type nd version).
#Ensure that server authentication takes place - The connection is terminated on a failure.
print("ip ssh stricthostkeycheck")

# |-- Console and AUX Ports
print("line aux 0")
print("transport input none")
print("transport output none")
print("no exec exec-timeout 0 1")
print("no password")
print("exit")

# |-- Control vty and tty Lines
print("line vty 0 4")
print("exec-timeout 5 0")
print("access-class ACL-VTY-IN in")
print("exit")
print("ip access-list extended ACL-VTY-IN")
print(" permit ip host <trusted-management-stations> any")
print(" deny ip any any")
#  To-Do: Replace placeholders with actual values

# |-- Control Transport for vty and tty Lines
print("line vty 0 4")
print("transport input ssh")
print("transport output none")

# \-- Warning Banners
print("banner login X")
print("+----------------------------------------------------------------------------+")
print("|  You are accessing a U.S. Government (USG) Information System (IS) that    |")
print("|  is provided for USG-authorized use only.                                  |")
print("|                                                                            |")
print("|  By using this IS (which includes any device attached to this IS), you     |")
print("|  consent to the following conditions:                                      |")
print("|                                                                            |")
print("|  -The USG routinely intercepts and monitors communications on this IS for  |")
print("|   purposes including, but not limited to, penetration testing, COMSEC      |")
print("|   monitoring, network operations and defense, personnel misconduct (PM),   |")
print("|   law enforcement (LE), and counterintelligence (CI) investigations.       |")
print("|                                                                            |")
print("|  -At any time, the USG may inspect and seize data stored on this IS.       |")
print("|                                                                            |")
print("|  -Communications using, or data stored on, this IS are not private, are    |")
print("|   subject to routine monitoring, interception, and search, and may be      |")
print("|   disclosed or used for any USG-authorized purpose.                        |")
print("|                                                                            |")
print("|  -This IS includes security measures (e.g., authentication and access      |")
print("|   controls) to protect USG interests--not for your personal benefit or     |")
print("|   privacy.                                                                 |")
print("|                                                                            |")
print("|  -Notwithstanding the above, using this IS does not constitute consent     |")
print("|   to PM, LE or CI investigative searching or monitoring of the content     |")
print("|   of privileged communications, or work product, related to personal       |")
print("|   representation or services by attorneys, psychotherapists, or clergy,    |")
print("|   and their assistants. Such communications and work product are private   |")
print("|   and confidential. See User Agreement for details.                        |")
print("+----------------------------------------------------------------------------+")
print("X")


# Authentication, Authorization, and Accounting
# |-- TACACS+ Authentication
print("aaa new-model")
print("aaa authentication login default group tacacs+")
print("tacacs server <server_name>")
print(" address ipv4 <tacacs_server_ip_address>")
print(" key <key>")

# | |-- Method Lists

# | \-- TACACS+ Over TLS 1.3

# |-- Authentication Fallback

# |-- Use of Type 7 Passwords

# |-- TACACS+ Command Authorization

# |-- TACACS+ Command Accounting

# |-- RADIUS Authentication

# Fortify the Simple Network Management Protocol

# |-- SNMP Community Strings
# |-- SNMP Community Strings with ACLs
# |-- Infrastructure ACLs
# |-- SNMP Views
# |-- SNMP Version 3
# |-- Management Plane Protection
# Logging Best Practices
# |-- Send Logs to a Central Location
# |-- Logging Level
# |-- Do Not Log to Console or Monitor Sessions
# |-- Use Buffered Logging
# |-- Configure Logging Source Interface
# |-- Configure Logging Timestamps
# Cisco IOS XE Software Configuration Management
# |-- Configuration Replace and Configuration Rollback
# |-- Exclusive Configuration Change Access
# |-- Digitally Signed Cisco Software
# |-- Configuration Change Notification and Logging
# Control Plane
# General Control Plane Hardening
# |-- IP ICMP Redirects
# |-- ICMP Unreachables
# |-- Proxy ARP
# |-- NTP Control Messages
# Limit CPU Impact of Control Plane Traffic
# |-- Understand Control Plane Traffic
# |-- Infrastructure ACLs
# |-- Receive ACLs
# |-- CoPP
# |-- Control Plane Protection
# |-- Hardware Rate Limiters
# Secure BGP
# |-- TTL-based Security Protections
# |-- BGP Peer Authentication with MD5
# |-- Configure Maximum Prefixes
# |-- Filter BGP Prefixes with Prefix Lists
# |-- Filter BGP Prefixes with Autonomous System Path Access Lists
# Secure Interior Gateway Protocols
# Routing Protocol Authentication and Verification with Message Digest 5
# |-- Passive-Interface Commands
# |-- Route Filtering
# |-- Routing Process Resource Consumption
# Secure First Hop Redundancy Protocols
# Data Plane
# General Data Plane Hardening
IP Options Selective Drop
Disable IP Source Routing
Disable ICMP Redirects
Disable or Limit IP Directed Broadcasts
Filter Transit Traffic with Transit ACLs
ICMP Packet Filtering
Filter IP Fragments
ACL Support for Filtering IP Options
Anti-Spoofing Protections
Unicast RPF
IP Source Guard
Port Security
Anti-Spoofing ACLs
Limit CPU Impact of Data Plane Traffic
Features and Traffic Types that Impact the CPU
Filter on TTL Value
Filter on the Presence of IP Options
Control Plane Protection
Traffic Identification and Traceback
NetFlow
Classification ACLs
Access Control with PACLs
Isolated VLANs
Community VLANs
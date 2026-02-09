print("! Cisco IOS XE Software Hardening Guide")
print("! Version 1.0")
print("!================================")

def print_lines(lines):
    for line in lines:
        print(line)

hardening_guide_general_management_plane_hardening = [
    "Starting system initialization...",
    "Loading configuration files",
    "System ready"
]

print_lines(hardening_guide_general_management_plane_hardening)

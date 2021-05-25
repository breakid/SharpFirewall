# SharpFirewall
C# application for adding, removing, and listing Windows Firewall rules.

Unfortunately, I wasn't able to get it to compile directly with CSC, so Visual Studio is required. If anyone figures out how to compile with CSC, please let me know! "C:\Windows\System32\FirewallAPI.dll" is a required reference file.

### Usage

#### Add Program Rule

    SharpFirewall.exe -A <rule_name> <application_path>

Adds a new program rule for the specified application. Absolute path must be used. Applies to current profile.


#### Add Port Rule

    SharpFirewall.exe -A <rule_name> <allow|block> <in|out> <protocol> <src_host> <src_ports> <dst_host> <dst_port> [--domain] [--private] [--public] [-F]

Adds a new port rule using the specified parameters. 
"*" and "ANY" are synonymous.
Only supports TCP, UDP, and ANY protocols.
If no profile (domain, private, or public) is specified, the rule will be applied to all profiles.
Use the force option (-F or /F) to add a new rule with an existing name.


#### Remove Rule By Name

    SharpFirewall.exe -D <rule_name>

Deletes all rules with the specified name, if one or more exist.


#### Remove Rule By Program Path

    SharpFirewall.exe -D <application_path>

Deletes the rule for the specified application, if it exists. If the 
specified argument is not a valid path, it will be interpreted as a 
rule name.


#### List Rules

    SharpFirewall.exe [/V]

By default, will list all valid, enabled rules from the current 
profile in table format. /V can be used to enable verbose mode, which 
will print attributes of all rules (enabled / disabled; valid / 
invalid, etc.). Directionality is used to determine source / 
destination addresses and ports, then omitted from the final output.


### Examples

    SharpFirewall.exe -A TestRule allow in TCP 192.168.10.5 * 192.168.10.10 80,443

This will create a new rule called "TestRule" that allows all inbound TCP traffic from any port on 192.168.10.5 to 192.168.10.10 on ports 80 and 443.


    SharpFirewall.exe -A TestRule block out UDP * * 8.8.8.8 53 /F

This will create a new rule called "TestRule2" that blocks all outbound UDP traffic from any source host/port to 8.8.8.8 on port 53 (i.e., blocks Google DNS). The /F ensures the rule will be created even if a rule with the same name from the example above already exists.


    SharpFirewall.exe -D TestRule

This will delete all rules named "TestRule".


    SharpFirewall.exe -D C:\Users\Dan\AppData\Roaming\Zoom\bin\Zoom.exe

This will delete the program rule for the Zoom application.
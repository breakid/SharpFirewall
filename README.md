# SharpFirewall
C# application for interacting with Windows Firewall. Currently it only lists firewall rules; however, potential future versions may allow adding and removing rules as well.

By default, it will list all valid, enabled rules from the current profile in table format. /V can be used to enable verbose mode, which will print attributes of all rules (enabled / disabled; valid / invalid, etc.). Directionality is used to determine source / destination addresses and ports, then omitted from the final output.

Unfortunately, I wasn't able to get it to compile directly with CSC, so Visual Studio is required. If anyone figures out how to compile with CSC, please let me know! "C:\Windows\System32\FirewallAPI.dll" is a required reference file.

#### Usage
    list_firewall_rules.exe [/V]
    
        /V    Verbose mode
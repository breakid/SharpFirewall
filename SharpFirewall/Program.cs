// Heavily modified from Original Source: https://stackoverflow.com/questions/10342260/is-there-any-net-api-to-get-all-the-firewall-rules

// To Compile:
//   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /reference:"C:\Windows\System32\FirewallAPI.dll" /t:exe /out:bin\list_firewall_rules.exe list_firewall_rules.cs

// /reference:"C:\Windows\System32\hnetcfg.dll" 
using System;
using NetFwTypeLib;

namespace SharpFirewall
{
    class Program
    {
        public static void PrintUsage()
        {
            Console.WriteLine(@"Lists firewall rules

By default, it will list all valid, enabled rules from the current profile in table format. /V can be used to enable verbose mode, which will print attributes of all rules (enabled / disabled; valid / invalid, etc.). Directionality is used to determine source / destination addresses and ports, then omitted from the final output.

USAGE:
    list_firewall_rules.exe [/V]
        
        /V    Verbose mode");
            Console.WriteLine("\nDONE");
        }

        // Reference: http://forums.purebasic.com/english/viewtopic.php?f=12&t=33608
        static string GetProfile(int profile)
        {
            switch (profile)
            {
                case 1:
                    return "Domain";
                case 2:
                    return "Private";
                case 3:
                    return "Domain, Private";
                case 4:
                    return "Public";
                case 5:
                    return "Domain, Public";
                case 6:
                    return "Private, Public";
                case 7:
                case 2147483647:
                    return "All";
                default:
                    return profile.ToString();
            }
        }

        // Reference: https://github.com/TechnitiumSoftware/TechnitiumLibrary/blob/master/TechnitiumLibrary.Net.Firewall/WindowsFirewall.cs
        static string GetProtocol(int protocol)
        {
            switch (protocol)
            {
                case -1:
                    return "Unknown";
                case 0:
                    return "ANY";
                case 1:
                    return "ICMPv4";
                case 2:
                    return "IGMP";
                case 4:
                    return "IPv4";
                case 6:
                    return "TCP";
                case 17:
                    return "UDP";
                case 41:
                    return "IPv6";
                case 47:
                    return "GRE";
                case 58:
                    return "ICMPv6";
                default:
                    return "Invalid"; // protocol.ToString();
            }
        }

        // Reference: https://docs.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_rule_direction
        // Reference: http://forums.purebasic.com/english/viewtopic.php?f=12&t=33608
        static string GetDirection(int direction)
        {
            switch (direction)
            {
                case 1:
                    return "Inbound";
                case 2:
                    return "Outbound";
                default:
                    return "Invalid"; // direction.ToString();
            }
        }

        // Reference: https://docs.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_rule_direction
        static string GetAction(int action)
        {
            switch (action)
            {
                case 0:
                    return "Block";
                case 1:
                    return "Allow";
                default:
                    return "Invalid"; // action.ToString();
            }
        }

        static void Main(string[] args)
        {
            bool verbose = false;

            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                switch (arg.ToUpper())
                {
                    case "-V":
                    case "/V":
                        verbose = true;
                        break;
                    case "/?":
                        PrintUsage();
                        return;
                }
            }

            try
            {
                Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

                string[] columns = new string[] { "Action", "Protocol", "Source Address", "Source Ports", "Destination Address", "Destination Ports", "Application" };
                int col_spacer = 2;
                string direction;
                string profile;
                string protocol;
                string src_addr;
                string src_ports;
                string dest_addr;
                string dest_ports;
                string current_profile = GetProfile(fwPolicy2.CurrentProfileTypes);

                if (!verbose)
                {
                    Console.WriteLine(string.Format("\nCurrent Profile: {0}\n", current_profile));

                    // Dynamically build a table header and separator from a list of column names
                    string header = "";
                    string separator = "";

                    foreach (string col in columns)
                    {
                        header += col.PadRight(col.Length + col_spacer);
                        separator += $"{new String('-', col.Length)}{new String(' ', col_spacer)}";
                    }

                    Console.WriteLine(header);
                    Console.WriteLine(separator);
                }

                foreach (INetFwRule rule in fwPolicy2.Rules)
                {
                    direction = GetDirection((int)rule.Direction);
                    protocol = GetProtocol((int)rule.Protocol);

                    // Determine source / destination based on directionality of the traffic
                    // Because explicitly stating source and destination makes way more sense than manually determining it from local / remote and directionality of traffic
                    if (direction == "Inbound")
                    {
                        src_addr = rule.RemoteAddresses ?? "";
                        src_ports = rule.RemotePorts ?? "";
                        dest_addr = rule.LocalAddresses ?? "";
                        dest_ports = rule.LocalPorts ?? "";
                    }
                    else if (direction == "Outbound")
                    {
                        src_addr = rule.LocalAddresses ?? "";
                        src_ports = rule.LocalPorts ?? "";
                        dest_addr = rule.RemoteAddresses ?? "";
                        dest_ports = rule.RemotePorts ?? "";
                    }
                    else
                    {
                        src_addr = "";
                        src_ports = "";
                        dest_addr = "";
                        dest_ports = "";

                        // Invalid Direction; only print entry in verbose mode
                        if (!verbose)
                        {
                            continue;
                        }
                    }

                    if (verbose)
                    {
                        Console.WriteLine("Name: " + rule.Name);
                        Console.WriteLine("  Grouping: " + rule.Grouping);
                        Console.WriteLine("  Description: " + rule.Description);
                        Console.WriteLine("  Application: " + rule.ApplicationName);
                        Console.WriteLine("  Service Name: " + rule.serviceName);
                        Console.WriteLine("  Profile: " + GetProfile((int)rule.Profiles));
                        Console.WriteLine("  Enabled: " + rule.Enabled);
                        Console.WriteLine("  Action: " + GetAction((int)rule.Action));
                        Console.WriteLine("  Direction: " + direction);
                        Console.WriteLine("  Protocol: " + protocol);

                        Console.WriteLine("  Source Addresses: " + src_addr);
                        Console.WriteLine("  Source Ports: " + src_ports);
                        Console.WriteLine("  Destination Addresses: " + dest_addr);
                        Console.WriteLine("  Destination Ports: " + dest_ports);
                        Console.WriteLine("  ICMP Codes: " + rule.IcmpTypesAndCodes);
                        Console.WriteLine("  InterfaceTypes: " + rule.InterfaceTypes);
                        Console.WriteLine("  Interfaces: " + rule.Interfaces);
                        Console.WriteLine("");
                    }
                    else
                    {
                        // Skip disabled rules and invalid protocols in non-verbose mode
                        if (!rule.Enabled || protocol == "Invalid")
                        {
                            continue;
                        }

                        profile = GetProfile((int)rule.Profiles);

                        // Only list rules from the current profile
                        if (profile == "All" || profile.Contains(current_profile))
                        {
                            Console.WriteLine($"{GetAction((int)rule.Action),-8}{protocol,-10}{src_addr,-16}{src_ports,-14}{dest_addr,-21}{dest_ports,-19}{rule.ApplicationName}");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] ERROR: {0}", e.Message);
            }

            Console.WriteLine("\nDONE");
        }
    }
}

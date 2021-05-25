// Heavily modified from Original Source: https://stackoverflow.com/questions/10342260/is-there-any-net-api-to-get-all-the-firewall-rules

using System;
using System.IO;
using NetFwTypeLib;

namespace SharpFirewall
{
    class Program
    {
        public static void PrintUsage()
        {
            Console.WriteLine(@"Add, remove, or list firewall rules

USAGE:
    SharpFirewall.exe [/V]

        By default, will list all valid, enabled rules from the current 
        profile in table format. /V can be used to enable verbose mode, which 
        will print attributes of all rules (enabled / disabled; valid / 
        invalid, etc.). Directionality is used to determine source / 
        destination addresses and ports, then omitted from the final output.


    SharpFirewall.exe -A <rule_name> <application_path>

        Adds a new program rule for the specified application.
        Absolute path must be used. Applies to current profile.


    SharpFirewall.exe -A <rule_name> <allow|block> <in|out> <protocol> 
        <src_host> <src_ports> <dst_host> <dst_port> [--domain] [--private] 
        [--public] [-F]

        Adds a new port rule using the specified parameters. If no profile 
        (domain, private, or public) is specified, the rule will be applied to 
        all profiles.

        Only supports TCP, UDP, and ANY protocols

        Use the force option (-F or /F) to add a new rule with an existing name


    SharpFirewall.exe -D <rule_name>

        Deletes all rules with the specified name, if one or more exist


    SharpFirewall.exe -D <application_path>

        Deletes the rule for the specified application, if it exists. If the 
        specified argument is not a valid path, it will be interpreted as a 
        rule name.

DONE");
        }


        // Reference: http://forums.purebasic.com/english/viewtopic.php?f=12&t=33608
        static string GetProfileString(int profile)
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
        static string GetProtocolString(int protocol)
        {
            switch (protocol)
            {
                case -1:
                    return "Unknown";
                case 0:
                case 256:
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
        static string GetDirectionString(int direction)
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
        static string GetActionString(int action)
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


        // Source: https://stackoverflow.com/questions/3261451/using-a-bitmask-in-c-sharp
        [Flags]
        public enum Profile
        {
            None = 0,
            Domain = 1,
            Private = 2,
            Public = 4
        }


        // The casts to object in the below code are an unfortunate necessity due to
        // C#'s restriction against a where T : Enum constraint. (There are ways around
        // this, but they're outside the scope of this simple illustration.)
        public static class FlagsHelper
        {
            public static bool IsSet<T>(T flags, T flag) where T : struct
            {
                int flagsValue = (int)(object)flags;
                int flagValue = (int)(object)flag;

                return (flagsValue & flagValue) != 0;
            }

            public static void Set<T>(ref T flags, T flag) where T : struct
            {
                int flagsValue = (int)(object)flags;
                int flagValue = (int)(object)flag;

                flags = (T)(object)(flagsValue | flagValue);
            }

            public static void Unset<T>(ref T flags, T flag) where T : struct
            {
                int flagsValue = (int)(object)flags;
                int flagValue = (int)(object)flag;

                flags = (T)(object)(flagsValue & (~flagValue));
            }
        }


        static bool ParsePortArgs(string[] args, ref int i, ref int action, ref string direction, ref int protocol, ref string src_host, ref string src_ports, ref string dst_host, ref string dst_ports)
        {
            bool success = true;

            // Error out if there are not 7 positional arguments
            if (i + 6 < args.Length)
            {
                // Parse action
                switch (args[i].ToLower())
                {
                    case "block":
                        action = 0;
                        break;
                    case "allow":
                        action = 1;
                        break;
                    default:
                        success = false;
                        Console.Error.WriteLine("ERROR: Invalid action ({0})", args[i]);
                        break;
                }

                i++;

                // Parse direction
                direction = args[i].ToLower();

                if (!direction.Equals("in") && !direction.Equals("out"))
                {
                    success = false;
                    Console.Error.WriteLine("ERROR: Invalid direction ({0})", args[i]);
                }

                i++;

                // Parse protocol
                // See NetFwTypeLib.NET_FW_IP_PROTOCOL_
                switch (args[i].ToUpper())
                {
                    case "*":
                    case "ANY":
                        protocol = 256;
                        break;
                    case "TCP":
                        protocol = 6;
                        break;
                    case "UDP":
                        protocol = 17;
                        break;
                    default:
                        success = false;
                        Console.Error.WriteLine("ERROR: Invalid protocol ({0})", args[i]);
                        break;
                }

                i++;

                // Parse host and port info
                src_host = args[i++];
                src_ports = args[i++];
                dst_host = args[i++];
                dst_ports = args[i];

                // Normalize values
                if (src_host.ToUpper().Equals("ANY"))
                {
                    src_host = "*";
                }

                if (src_ports.ToUpper().Equals("ANY"))
                {
                    src_ports = "*";
                }

                if (dst_host.ToUpper().Equals("ANY"))
                {
                    dst_host = "*";
                }

                if (dst_ports.ToUpper().Equals("ANY"))
                {
                    src_ports = "*";
                }
            }
            else
            {
                success = false;
                Console.Error.WriteLine("ERROR: Insufficient arguments");
            }

            return success;
        }


        // Source: https://stackoverflow.com/questions/113755/programmatically-add-an-application-to-windows-firewall
        static void AddProgramRule(string name, string applicationPath)
        {
            try
            {
                // Abort if applicationPath does not exist
                if (!File.Exists(applicationPath))
                {
                    Console.Error.WriteLine("ERROR: Invalid path ({0})", applicationPath);
                    return;
                }

                Type fwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
                INetFwMgr fwMgr = (INetFwMgr)Activator.CreateInstance(fwMgrType);
                Type authAppType = Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication", false);

                INetFwAuthorizedApplication appInfo = (INetFwAuthorizedApplication)Activator.CreateInstance(authAppType);
                appInfo.Name = name;
                appInfo.ProcessImageFileName = applicationPath;
                fwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications.Add(appInfo);

                Console.WriteLine("Added Program Rule: {0}", applicationPath);
            } catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
            }
        }


        static void AddPortRule(string name, int profiles, int action, string direction, int protocol, string srcHost, string srcPorts, string dstHost, string dstPorts, bool force)
        {
            if (string.IsNullOrEmpty(name))
            {
                Console.Error.WriteLine("ERROR: No rule name specified");
                return;
            }

            // "if protocol is set to "any", ports will not be allowed"
            // Source: https://stackoverflow.com/questions/32632609/value-out-of-range-exception-when-setting-a-string-member-of-inetfwrule
            if (protocol == 256)
            {
                srcPorts = "N/A";
                dstPorts = "N/A";
            }

            try
            {
                // Source: https://stackoverflow.com/questions/15409790/adding-an-application-firewall-rule-to-both-private-and-public-networks-via-win7
                // Initialize new rule
                INetFwRule2 newRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                newRule.Name = name;
                newRule.Enabled = true;
                newRule.Profiles = profiles;
                newRule.Action = (NET_FW_ACTION_)action;
                newRule.Protocol = protocol;

                if (direction.Equals("in"))
                {
                    newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    newRule.RemoteAddresses = srcHost;
                    newRule.LocalAddresses = dstHost;

                    // Only set ports if protocol != ANY
                    if (protocol != 256)
                    {
                        newRule.RemotePorts = srcPorts;
                        newRule.LocalPorts = dstPorts;
                    }
                }
                else
                {
                    newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                    newRule.LocalAddresses = srcHost;
                    newRule.RemoteAddresses = dstHost;

                    // Only set ports if protocol != ANY
                    if (protocol != 256)
                    {
                        newRule.LocalPorts = srcPorts;
                        newRule.RemotePorts = dstPorts;
                    }
                }

                // Now add the rule
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

                // Unless the force option is specified, verify no rule exists with the given name (duplicate rule names make deleting messier)
                if (!force)
                {
                    foreach (INetFwRule rule in firewallPolicy.Rules)
                    {
                        if (rule.Name.Equals(name))
                        {
                            Console.Error.WriteLine("ERROR: Detected existing rule named '{0}'; use force option to override", name);
                            return;
                        }
                    }
                }

                firewallPolicy.Rules.Add(newRule);

                Console.WriteLine("Added Port Rule: {0}", name);
                Console.WriteLine("  Profile(s)        : {0}", (Profile)profiles);
                Console.WriteLine("  Action            : {0}", GetActionString(action));
                Console.WriteLine("  Direction         : {0}", (direction + "bound").ToUpper());
                Console.WriteLine("  Protocol          : {0}", GetProtocolString(protocol));
                Console.WriteLine("  Source Host       : {0}", srcHost);
                Console.WriteLine("  Source Ports      : {0}", srcPorts);
                Console.WriteLine("  Destination Host  : {0}", dstHost);
                Console.WriteLine("  Destination Ports : {0}", dstPorts);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
            }
        }

        static void DeleteRuleByName(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName))
            {
                Console.Error.WriteLine("ERROR: No rule name specified");
                return;
            }

            // Source: https://stackoverflow.com/questions/29890644/c-sharp-firewall-delete-specific-entry
            try
            {
                bool ruleFound = false;
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                
                foreach (INetFwRule rule in firewallPolicy.Rules)
                {
                    if (rule.Name.Equals(ruleName))
                    {
                        ruleFound = true;
                        firewallPolicy.Rules.Remove(ruleName);
                        Console.WriteLine("Deleted Rule: {0}", ruleName);
                        // Do not return immediately in case there are other rules with the same name
                    }
                }

                if (!ruleFound)
                {
                    Console.Error.WriteLine("No Rule Found Named: '{0}'", ruleName);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
            }
        }


        static void DeleteRuleByPath(string applicationPath)
        {
            try
            {
                bool ruleFound = false;
                Type fwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
                INetFwMgr fwMgr = (INetFwMgr)Activator.CreateInstance(fwMgrType);

                foreach (INetFwAuthorizedApplication app in fwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications)
                {
                    if (app.ProcessImageFileName.ToLower() == applicationPath.ToLower())
                    {
                        ruleFound = true;
                        fwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications.Remove(applicationPath);
                        Console.WriteLine("Deleted Program Rule: {0}", applicationPath);
                    }
                }

                if (!ruleFound)
                {
                    Console.Error.WriteLine("ERROR: No Program Rule Found for: {0}", applicationPath);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: {0}", ex.Message);
            }
        }


        static void ListRules(bool verbose)
        {
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
                string current_profile = GetProfileString(fwPolicy2.CurrentProfileTypes);

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
                    direction = GetDirectionString((int)rule.Direction);
                    protocol = GetProtocolString((int)rule.Protocol);

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
                        Console.WriteLine("  Profile: " + GetProfileString((int)rule.Profiles));
                        Console.WriteLine("  Enabled: " + rule.Enabled);
                        Console.WriteLine("  Action: " + GetActionString((int)rule.Action));
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

                        profile = GetProfileString((int)rule.Profiles);

                        // Only list rules from the current profile
                        if (profile == "All" || profile.Contains(current_profile))
                        {
                            Console.WriteLine($"{GetActionString((int)rule.Action),-8}{protocol,-10}{src_addr,-16}{src_ports,-14}{dest_addr,-21}{dest_ports,-19}{rule.ApplicationName}");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] ERROR: {0}", e.Message);
            }
        }


        static void Main(string[] args)
        {
            string command = "list";
            string type = "port";
            bool force = false;
            bool verbose = false;
            string name = "";
            string applicationPath = "";
            string direction = "in";
            int action = 1;
            int protocol = 0;
            string srcHost = "*";
            string dstHost = "*";
            string srcPorts = "*";
            string dstPorts = "*";
            Profile profiles = 0;

            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                switch (arg.ToUpper())
                {
                    case "-A":
                    case "/A":
                    case "--ADD":
                    case "/ADD":
                        command = "add";
                        i++;

                        // Add option takes at least 2 arguments; abort if they are not provided
                        if (i + 1 >= args.Length)
                        {
                            Console.Error.WriteLine("ERROR: Missing argument(s)");
                            Console.WriteLine("\nDONE");
                            return;
                        }

                        // If there are only two arguments after the add switch, assume it's an application rule; otherwise assume a port rule
                        if (i + 2 == args.Length || (i + 2 < args.Length && (args[i + 2].StartsWith("-") || args[i + 2].StartsWith("/"))))
                        {
                            type = "app";
                            name = args[i++];
                            applicationPath = args[i];
                        }
                        else if (i < args.Length)
                        {
                            type = "port";
                            name = args[i++];
                            if (!ParsePortArgs(args, ref i, ref action, ref direction, ref protocol, ref srcHost, ref srcPorts, ref dstHost, ref dstPorts))
                            {
                                Console.WriteLine("\nDONE");
                                return;
                            }
                        }

                        break;
                    case "-F":
                    case "/F":
                        force = true;
                        break;
                    case "-D":
                    case "/D":
                    case "--DELETE":
                    case "/DELETE":
                        command = "delete";
                        i++;

                        if (i < args.Length)
                        {
                            // Assume application rule deletion
                            type = "app";
                            applicationPath = args[i];

                            // If the specified argument is not a valid file path, treat it as a rule name
                            if (!File.Exists(applicationPath))
                            {
                                type = "port";
                                name = args[i];
                            }
                        }
                        else
                        {
                            Console.Error.WriteLine("ERROR: Missing argument");
                            Console.WriteLine("\nDONE");
                            return;
                        }

                        break;
                    case "--DOMAIN":
                    case "/DOMAIN":
                        FlagsHelper.Set(ref profiles, Profile.Domain);
                        break;
                    case "--PRIVATE":
                    case "/PRIVATE":
                        FlagsHelper.Set(ref profiles, Profile.Private);
                        break;
                    case "--PUBLIC":
                    case "/PUBLIC":
                        FlagsHelper.Set(ref profiles, Profile.Public);
                        break;
                    case "-V":
                    case "/V":
                        verbose = true;
                        break;
                    case "/?":
                        PrintUsage();
                        return;
                }
            }

            // If no profile is specified, default to all profiles
            if (profiles == Profile.None)
            {
                profiles = (Profile)7;
            }

            switch (command)
            {
                case "add":
                    if (type.Equals("port"))
                    {
                        AddPortRule(name, (int)profiles, action, direction, protocol, srcHost, srcPorts, dstHost, dstPorts, force);
                    }
                    else if (type.Equals("app"))
                    {
                        AddProgramRule(name, applicationPath);
                    }
                    else
                    {
                        Console.Error.WriteLine("ERROR: Invalid rule type; must specify either port or program");
                    }
                    
                    break;
                case "delete":

                    if (type.Equals("port"))
                    {
                        DeleteRuleByName(name);
                    }
                    else if (type.Equals("app"))
                    {
                        DeleteRuleByPath(applicationPath);
                    }
                    else
                    {
                        Console.Error.WriteLine("ERROR: Invalid rule type; must specify either port or program");
                    }
                    
                    break;
                case "list":
                    ListRules(verbose);
                    break;
                default:
                    Console.Error.WriteLine("ERROR: Unsupported operation ({0})", command);
                    break;
            }

            Console.WriteLine("\nDONE");
        }
    }
}

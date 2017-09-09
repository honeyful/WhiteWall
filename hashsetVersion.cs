using System;
using System.IO;
using System.Collections.Generic;
using NetFwTypeLib;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;

namespace WhiteWall
{
    class Program
    {
        static HashSet<string> whiteList = new HashSet<string>();

        static void Main(string[] args)
        {
            Console.Title = "WhiteWall";

            loadSettings();

            while (true)
            {
                Console.WriteLine("+++++++++++++++");
                Console.WriteLine("0. Exit");
                Console.WriteLine("1. Apply Whitelist - Verify Signature");
                Console.WriteLine("2. Apply Whitelist - No Verify Signatrue");
                Console.WriteLine("3. Add Whitelist");
                Console.WriteLine("4. Remove Whitelist");
                Console.WriteLine("5. View Whitelist");
                Console.WriteLine("6. Reset Firewall");
                Console.WriteLine("+++++++++++++++");
                Console.Write(">>>");

                switch(int.Parse(Console.ReadLine()))
                {
                    case 0: Environment.Exit(0); break;
                    case 1: fwReset(); applyWhitelistVerify(); break;
                    case 2: fwReset(); applyWhitelistNormal(); break;
                    case 3: addWhitelist(); break;
                    case 4: removeWhitelist(); break;
                    case 5: viewWhitelist(); break;
                    case 6: resetFirewall();  break;
                }
            }
        }

        static void loadSettings()
        {
            if (Properties.Settings.Default.whitelist == null)
            {
                Properties.Settings.Default.whitelist = new StringCollection();
            }

            foreach (var i in Properties.Settings.Default.whitelist)
                whiteList.Add(i);
        }

        static void saveSettings()
        {
            Properties.Settings.Default.whitelist = new StringCollection();
            foreach (var i in whiteList)
                Properties.Settings.Default.whitelist.Add(i);

            Properties.Settings.Default.Save();
        }

        static void applyWhitelistVerify()
        {
            foreach(var i in whiteList)
            {
                if(File.Exists(i))
                {
                    if(checkSignature(i))
                    {
                        Console.WriteLine($"[+]{i}");
                        allowRule(i);
                    }
                    else
                    {
                        Console.WriteLine($"[-]{i}");
                        blockRule(i);
                    }
                }
                else
                {
                    foreach(var f in GetFilesRecursive(i))
                    {
                        if (checkSignature(f))
                        {
                            Console.WriteLine($"[+]{f}");
                            allowRule(f);
                        }
                        else
                        {
                            Console.WriteLine($"[-]{f}");
                            blockRule(f);
                        }
                    }
                }
            }

            fwInitRule(true);

            Console.WriteLine("Done.");
        }

        static void applyWhitelistNormal()
        {
            foreach (var i in whiteList)
            {
                if (File.Exists(i))
                {
                    Console.WriteLine($"[+]{i}");
                    allowRule(i);
                }
                else
                {
                    foreach (var f in GetFilesRecursive(i))
                    {
                        Console.WriteLine($"[+]{f}");
                        allowRule(f);
                    }
                }
            }

            fwInitRule(true);

            Console.WriteLine("Done.");
        }

        static void addWhitelist()
        {
            while (true)
            {
                Console.Write("Path(Back to Menu)>>>");
                var f = Console.ReadLine();
                if (f.ToLower().Equals("back")) return;
                if (File.Exists(f))
                {
                    whiteList.Add(f);
                }
                else if (Directory.Exists(f))
                {
                    whiteList.Add(f);
                }
                else
                {
                    Console.WriteLine("Invalid Path");
                }
                saveSettings();
            }
        }
        
        static void removeWhitelist()
        {
            while (true)
            {
                viewWhitelist();
                Console.Write("Remove(Back to Menu)>>>");
                var s = Console.ReadLine();
                if (s.ToLower().Equals("back")) return;
                try
                {
                    whiteList.Remove(s);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                saveSettings();
            }
        }

        static void viewWhitelist()
        {
            foreach(var i in whiteList)
            {
                Console.WriteLine($"[+] {i}");
            }
        }

        static void resetFirewall()
        {
            fwReset();
            Console.WriteLine("Reset");
        }

        #region Firewall

        static void fwInitRule(bool option)
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, option);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN, !option ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, option);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE, !option ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK);

            mgr.set_BlockAllInboundTraffic(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, option);
            mgr.set_DefaultInboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
            mgr.set_DefaultOutboundAction(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC, !option ? NET_FW_ACTION_.NET_FW_ACTION_ALLOW : NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
        }

        static void fwReset()
        {
            Type netFwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 mgr = (INetFwPolicy2)Activator.CreateInstance(netFwPolicy2Type);
            mgr.RestoreLocalFirewallDefaults();
        }


        static void allowRule(string fileName)
        {
            INetFwRule fwRule = (INetFwRule)Activator.CreateInstance(
                 Type.GetTypeFromProgID("HNetCfg.FWRule"));
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            fwRule.Enabled = true;
            fwRule.InterfaceTypes = "All";
            fwRule.Name = fileName.ToLower();
            fwRule.ApplicationName = fileName;
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            fwPolicy.Rules.Add(fwRule);
        }

        static void blockRule(string fileName)
        {
            INetFwRule fwRule = (INetFwRule)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FWRule"));
            fwRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwRule.Enabled = true;
            fwRule.InterfaceTypes = "All";
            fwRule.Name = fileName.ToLower();
            fwRule.ApplicationName = fileName;
            INetFwPolicy2 fwPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            fwRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            fwPolicy.Rules.Add(fwRule);
        }

        #endregion

        #region ETC
        static HashSet<string> GetFilesRecursive(string initial)
        {
            HashSet<string> result = new HashSet<string>();

            Stack<string> stack = new Stack<string>();

            stack.Push(initial);

            while ((stack.Count > 0))
            {
                string dir = stack.Pop();
                try
                {
                    foreach(var i in Directory.GetFiles(dir, "*.exe"))
                    {
                        result.Add(i);
                    }

                    string directoryName = null;
                    foreach (string directoryName_loopVariable in Directory.GetDirectories(dir))
                    {
                        directoryName = directoryName_loopVariable;
                        stack.Push(directoryName);
                    }

                }
                catch (Exception)
                {
                }
            }
            return result;
        }

        static bool checkSignature(string fileName)
        {
            var certChain = new X509Chain();
            var cert = default(X509Certificate2);
            bool isChainValid = false;
            try
            {
                var signer = X509Certificate.CreateFromSignedFile(fileName);
                cert = new X509Certificate2(signer);
            }
            catch
            {
                return isChainValid;
            }

            certChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            certChain.ChainPolicy.UrlRetrieval‎Timeout = new TimeSpan(0, 1, 0);
            certChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            isChainValid = certChain.Build(cert);

            return isChainValid;
        }
        #endregion

    }
}

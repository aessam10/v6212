using System;
using System.Collections.Generic;
using System.IO;
using Long.Kernel.Network.Game;

namespace Long.Kernel.Security.MsgLoader
{
    public class SystemBannedPC
    {
        public static Dictionary<string, BannedClient> BannedPool = new Dictionary<string, BannedClient>(StringComparer.OrdinalIgnoreCase);

        public class BannedClient
        {
            public uint HDSerial;
            public string HWID;
            public string IP;
            public string MACAddress;
            public string PlayerName;

            public override string ToString()
            {
                return $"{HDSerial}/{HWID}/{IP}/{MACAddress}/{PlayerName}";
            }
        }

        private static readonly string BanFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "BannedPC.txt");

        public static void Load()
        {
            try
            {
                BannedPool.Clear();
                if (File.Exists(BanFilePath))
                {
                    var lines = File.ReadAllLines(BanFilePath);
                    foreach (var line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";"))
                            continue;

                        var split = line.Split('/');
                        if (split.Length >= 5)
                        {
                            var client = new BannedClient
                            {
                                HDSerial = uint.TryParse(split[0], out var hd) ? hd : 0,
                                HWID = split[1],
                                IP = split[2],
                                MACAddress = split[3],
                                PlayerName = split[4]
                            };

                            if (!string.IsNullOrEmpty(client.HWID) && !BannedPool.ContainsKey(client.HWID))
                                BannedPool.Add(client.HWID, client);
                        }
                    }
                }
                Console.WriteLine($"[MsgLoader] Loaded [{BannedPool.Count}] banned machines.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MsgLoader Error] Failed to load BannedPC: {ex.Message}");
            }
        }

        public static bool IsBanned(string hwid, string mac, uint hdSerial)
        {
            if (!string.IsNullOrEmpty(hwid) && BannedPool.ContainsKey(hwid))
                return true;

            foreach (var ban in BannedPool.Values)
            {
                if (!string.IsNullOrEmpty(mac) && mac.Equals(ban.MACAddress, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (hdSerial != 0 && hdSerial == ban.HDSerial)
                    return true;
            }
            return false;
        }

        public static bool AddBan(GameClient client, string hwid, string mac, uint hdSerial)
        {
            if (string.IsNullOrEmpty(hwid))
                return false;

            if (!BannedPool.ContainsKey(hwid))
            {
                var banned = new BannedClient
                {
                    HWID = hwid,
                    MACAddress = mac,
                    HDSerial = hdSerial,
                    IP = client?.IpAddress ?? "0.0.0.0",
                    PlayerName = client?.Character?.Name ?? "Unknown"
                };

                BannedPool[hwid] = banned;
                try
                {
                    File.AppendAllText(BanFilePath, banned.ToString() + Environment.NewLine);
                }
                catch { }

                Console.WriteLine($"[MsgLoader] Added Machine Ban for player [{banned.PlayerName}], HWID: {hwid}");
                return true;
            }
            return false;
        }
    }
}

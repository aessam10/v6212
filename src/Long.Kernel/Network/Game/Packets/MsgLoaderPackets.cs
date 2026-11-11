using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Long.Kernel.Network.Game;
using Long.Kernel.Security.MsgLoader;
using Long.Network.Packets;

namespace Long.Kernel.Network.Game.Packets
{
    /// <summary>
    /// Packet: MsgLoader (0xDEB1 = 57009)
    /// Handles loader reports: Client file scanning, cheat detection, speedhack, aimbot, dll injection, etc.
    /// </summary>
    public sealed class MsgLoader : MsgBase<GameClient>
    {
        private byte[] rawBytes;

        public MsgLoader()
        {
            Type = PacketType.MsgLoader;
        }

        public override void Decode(byte[] bytes)
        {
            rawBytes = bytes;
        }

        public override Task ProcessAsync(GameClient client)
        {
            if (rawBytes == null || client.Guard == null)
                return Task.CompletedTask;

            var msg = new MsgGuardShield.MsgLoaderData(rawBytes, client.Guard);
            switch (msg.Type)
            {
                case MsgGuardShield.MsgLoaderData.LoaderMessage.ClientFilesScaning:
                    {
                        client.ActiveClient = true;
                        client.LoaderTime = DateTime.Now;

                        if (msg.GuardVersion != 113)
                        {
                            msg.strParam = "ERROR Changed Loader Version\r\nPlease update your client.";
                            Console.WriteLine($"[MsgLoader] Account: {client.Character?.Name ?? client.AccountIdentity.ToString()} disconnected due to old Loader Version [{msg.GuardVersion}].");
                            client.TerminateLoader = true;
                            client.Disconnect();
                            return Task.CompletedTask;
                        }

                        if (!MsgGuardShield.Validated(msg.Conquer, msg.MagicType, msg.MagicEffect, msg.C3_WDB, msg.DLL_Hash, msg.StrRes, msg.Data_Servers, out msg.strParam))
                        {
                            Console.WriteLine($"[MsgLoader] Cheat files detected for {client.Character?.Name}: {msg.strParam}");
                            MsgGuardShield.ReportLog(client.Character?.Name ?? "Unknown", $"Changed Game Files: {msg.strParam}");
                            _ = client.Guard.TerminateLoaderAsync("Security Violation", $"Modified files detected: {msg.strParam}");
                            return Task.CompletedTask;
                        }

                        // Request machine details
                        _ = client.Guard.RequestMachineInfoAsync();
                        break;
                    }

                default:
                    {
                        // Any cheat or abnormal operation reported by loader
                        string cheatName = msg.Type.ToString();
                        string extra = msg.strParam ?? "";
                        Console.WriteLine($"[MsgLoader CHEAT DETECTED] Player [{client.Character?.Name}] Reason: {cheatName} ({extra})");
                        MsgGuardShield.ReportLog(client.Character?.Name ?? "Unknown", $"{cheatName} - {extra}");

                        // Terminate client
                        _ = client.Guard.TerminateLoaderAsync("Security Violation", $"Cheating detected: {cheatName}");
                        break;
                    }
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Packet: MsgMachineInfo (0xDEB3 = 57011)
    /// Receives machine details: MachineName, MacAddress, HDSerial, VMware/VPS flags.
    /// </summary>
    public sealed class MsgMachineInfo : MsgBase<GameClient>
    {
        private byte[] rawBytes;

        public MsgMachineInfo()
        {
            Type = PacketType.MsgMachineInfo;
        }

        public override void Decode(byte[] bytes)
        {
            rawBytes = bytes;
        }

        public override Task ProcessAsync(GameClient client)
        {
            if (rawBytes == null || client.Guard == null)
                return Task.CompletedTask;

            var msg = new MsgGuardShield.MsgMachineInfoData(rawBytes, client.Guard);

            client.MacAddress = msg.MacAddress ?? "Unknown";

            if (msg.VMware)
                Console.Write("[VMware Machine] ");
            if (msg.VPSMachine)
                Console.Write("[VPS Machine] ");

            Console.WriteLine($"[MsgLoader] Player: [{client.Character?.Name ?? "Login"}] PC: '{msg.MachineName}' MAC: '{msg.MacAddress}' HD: {msg.HDSerial}");

            // Check if machine is banned
            if (SystemBannedPC.IsBanned(null, msg.MacAddress, msg.HDSerial))
            {
                Console.WriteLine($"[MsgLoader] BANNED PC attempted connection: {msg.MachineName} ({msg.MacAddress})");
                client.Disconnect();
                return Task.CompletedTask;
            }

            // Request process list to verify clean state
            _ = client.Guard.RequestOpenedProcessesAsync(MsgGuardShield.MsgOpenedProcessesData.Type.Start_ProcessQuery);

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Packet: MsgOpenedProcesses (0xDEAF = 57007)
    /// Receives query process checks and running executable scans.
    /// </summary>
    public sealed class MsgOpenedProcesses : MsgBase<GameClient>
    {
        private byte[] rawBytes;

        public MsgOpenedProcesses()
        {
            Type = PacketType.MsgOpenedProcesses;
        }

        public override void Decode(byte[] bytes)
        {
            rawBytes = bytes;
        }

        public override Task ProcessAsync(GameClient client)
        {
            if (rawBytes == null || client.Guard == null)
                return Task.CompletedTask;

            var msg = new MsgGuardShield.MsgOpenedProcessesData(rawBytes, client.Guard);
            if (msg == null)
                return Task.CompletedTask;

            if (!client.Guard.RequestProcess)
            {
                Console.WriteLine($"[MsgLoader] {client.Character?.Name} Disconnect: Unexpected OpenedProcesses response.");
                client.Disconnect();
                return Task.CompletedTask;
            }

            if (msg.ActionType == MsgGuardShield.MsgOpenedProcessesData.Type.Start_ProcessQuery)
            {
                client.QueryProcessList.Clear();
            }
            else if (msg.ActionType == MsgGuardShield.MsgOpenedProcessesData.Type.Insert_ProcessQuery)
            {
                var obj = new QueryProcess
                {
                    ExeName = msg.strParam,
                    Title = msg.strParam2,
                    MD5_Hash = msg.StrdwParam1,
                    SectionXxHash = msg.dwParam2,
                    SectionMemXxHash = msg.dwParam3
                };
                client.QueryProcessList[(uint)client.QueryProcessList.Count + 1] = obj;
            }
            else if (msg.ActionType == MsgGuardShield.MsgOpenedProcessesData.Type.Finish_ProcessQuery)
            {
                client.Guard.RequestProcess = false;

                bool cheatDetected = false;
                string detectedHack = "";

                foreach (var exe in client.QueryProcessList.Values)
                {
                    if (QueryProcess.ContainOnList(exe, out string matchedExe))
                    {
                        exe.IsHack = true;
                        cheatDetected = true;
                        detectedHack = matchedExe;
                        Console.WriteLine($"[MsgLoader ALERT] Player [{client.Character?.Name}] Suspect Program: [{matchedExe}] Process: [{exe.ExeName}]");
                    }
                }

                if (cheatDetected)
                {
                    MsgGuardShield.ReportLog(client.Character?.Name ?? "Unknown", $"Detected Hack Program: {detectedHack}");
                    _ = client.Guard.TerminateLoaderAsync("Security Alert", $"Unauthorized software detected: {detectedHack}");
                }
            }

            return Task.CompletedTask;
        }
    }
}

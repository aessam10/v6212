using Long.Kernel.Network.Game;
using Long.Network.Packets;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Long.Kernel.Security.MsgLoader
{
    public class QueryProcess
    {
        public string ExeName;
        public string Title;
        public string MD5_Hash;
        public uint SectionXxHash;
        public uint SectionMemXxHash;
        public bool IsHack;

        public static Dictionary<uint, QueryProcess> QueryProcessList = new Dictionary<uint, QueryProcess>();

        public static void Init()
        {
            var fileLocation = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "QueryProcess.txt");
            if (File.Exists(fileLocation))
            {
                QueryProcessList.Clear();
                uint counter = 0;
                var lines = File.ReadAllLines(fileLocation);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";"))
                        continue;
                    var split = line.Split(',');
                    if (split.Length < 5)
                        continue;

                    var pQuery = new QueryProcess
                    {
                        ExeName = split[0].Trim(),
                        Title = split[1].Trim(),
                        MD5_Hash = split[2].Trim()
                    };
                    uint.TryParse(split[3].Trim(), out pQuery.SectionXxHash);
                    uint.TryParse(split[4].Trim(), out pQuery.SectionMemXxHash);
                    QueryProcessList.Add(++counter, pQuery);
                }
            }
            Console.WriteLine($"[MsgLoader] Loaded successfully: [{QueryProcessList.Count}] QueryPrograms!");
        }

        public static bool ContainOnList(QueryProcess objList, out string matchedExeName)
        {
            if (objList == null)
            {
                matchedExeName = "None";
                return false;
            }

            string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LogCheats.txt");

            if (objList.Title == null || objList.Title.Length < 2)
                objList.Title = objList.ExeName ?? "Unknown";

            string newText = $"{objList.ExeName},{objList.Title},{objList.MD5_Hash},{objList.SectionXxHash},{objList.SectionMemXxHash}";

            try
            {
                if (!File.Exists(filePath) || !File.ReadLines(filePath).Contains(newText))
                {
                    File.AppendAllText(filePath, newText + Environment.NewLine);
                }
            }
            catch { }

            foreach (var obj in QueryProcessList.Values)
            {
                if ((!string.IsNullOrEmpty(obj.MD5_Hash) && obj.MD5_Hash.Equals(objList.MD5_Hash, StringComparison.OrdinalIgnoreCase))
                    || (obj.SectionXxHash != 0 && (obj.SectionXxHash == objList.SectionXxHash || obj.SectionXxHash == objList.SectionMemXxHash))
                    || (obj.SectionMemXxHash != 0 && (obj.SectionMemXxHash == objList.SectionMemXxHash || obj.SectionMemXxHash == objList.SectionXxHash))
                    || (!string.IsNullOrEmpty(obj.Title) && objList.Title.Contains(obj.Title, StringComparison.OrdinalIgnoreCase))
                    || (!string.IsNullOrEmpty(obj.ExeName) && objList.ExeName.Equals(obj.ExeName, StringComparison.OrdinalIgnoreCase)))
                {
                    matchedExeName = obj.ExeName;
                    return true;
                }
            }

            matchedExeName = "None";
            return false;
        }
    }

    public static class MsgGuardShield
    {
        private static string[] ConquerHashes = new string[2];
        private static string[] DLLHash = new string[2];
        private static string MagicHash, MagicEffectHash, StrResHash, DataServersHash;
        public static bool CheckConquer = false;
        public static void Load()
        {
            try
            {
                QueryProcess.Init();
                SystemBannedPC.Load();
                CheckConquer = true;
                ConquerHashes[0] = CalculateMD5(@"Files\Conquer.exe");
                MagicHash = CalculateMD5(@"Files\ini\magictype.dat");
                MagicEffectHash = CalculateMD5(@"Files\ini\MagicEffect.ini");
                StrResHash = CalculateMD5(@"Files\ini\StrRes.ini");
                DataServersHash = CalculateMD5(@"Files\Guard.dat");
                DLLHash[0] = CalculateMD5(@"Files\GuardShield.dll");
                Console.WriteLine("[MsgLoader] GuardShield initialized successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MsgLoader Error] Failed to load GuardShield: {ex.Message}");
            }
        }
        private static string CalculateMD5(string filename)
        {
            try
            {
                if (!File.Exists(filename))
                    return "";

                using var md5 = MD5.Create();
                using var stream = File.OpenRead(filename);
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                Console.WriteLine($"[MsgLoader] {filename} not found for hash calculation.");
            }
            return "";
        }

        public static bool Validated(string conquer, string magicType, string magicEffect, string c3_WDB, string dllHash, string strRes, string dataServers, out string fileChanged)
        {
            fileChanged = "";
            if (CheckConquer)
            {
                if (!string.IsNullOrEmpty(ConquerHashes[0]) && conquer != ConquerHashes[0])
                    fileChanged += " Conquer.exe";
            }
            if (!string.IsNullOrEmpty(MagicHash) && magicType != MagicHash)
                fileChanged += " magictype.dat";
            if (!string.IsNullOrEmpty(MagicEffectHash) && magicEffect != MagicEffectHash)
                fileChanged += " MagicEffect.ini";
            if (!string.IsNullOrEmpty(DLLHash[0]) && dllHash != DLLHash[0])
                fileChanged += " GuardShield.dll";
            if (!string.IsNullOrEmpty(StrResHash) && strRes != StrResHash)
                fileChanged += " StrRes.ini";
            if (!string.IsNullOrEmpty(DataServersHash) && dataServers != DataServersHash)
                fileChanged += " Guard.dat";

            return string.IsNullOrEmpty(fileChanged);
        }

        public static void ReportLog(string name, string reason)
        {
            try
            {
                string log = $"CHEAT [Player] {name} -- REASON: {(!string.IsNullOrEmpty(reason) ? reason : "Abnormal operation")}";
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LoaderLogg", "[Logs]");
                if (!Directory.Exists(logPath))
                    Directory.CreateDirectory(logPath);

                string file = Path.Combine(logPath, $"{DateTime.Now:yyyy-MM-dd}.txt");
                File.AppendAllText(file, $"[{DateTime.Now:HH:mm:ss}] {log}{Environment.NewLine}");
            }
            catch { }
        }

        public static byte[] RequestOpenedProcesses(MsgOpenedProcessesData.Type type = MsgOpenedProcessesData.Type.Start)
        {
            byte[] buffer = new byte[4 + 1 + 8];
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), (ushort)(buffer.Length - 8));
            BitConverter.TryWriteBytes(buffer.AsSpan(2, 2), (ushort)PacketType.MsgRequestOpenedProcesses);
            buffer[4] = (byte)type;
            return buffer;
        }

        public static byte[] RequestMachineInfo()
        {
            byte[] buffer = new byte[4 + 30 + 8];
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), (ushort)(buffer.Length - 8));
            BitConverter.TryWriteBytes(buffer.AsSpan(2, 2), (ushort)PacketType.MsgRequestMachineInfo);
            return buffer;
        }

        public static byte[] PingStatuesLoader(string pingStatuesMsg = "")
        {
            byte[] msgBytes = Encoding.Default.GetBytes(pingStatuesMsg ?? "");
            byte[] buffer = new byte[6 + msgBytes.Length + 2 + 8];
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), (ushort)(buffer.Length - 8));
            BitConverter.TryWriteBytes(buffer.AsSpan(2, 2), (ushort)PacketType.PingStatuesLoader);
            buffer[5] = (byte)msgBytes.Length;
            Array.Copy(msgBytes, 0, buffer, 6, msgBytes.Length);
            return buffer;
        }

        public static byte[] TerminateLoader(string messageCaption = "", string messageText = "")
        {
            byte[] captionBytes = Encoding.Default.GetBytes(messageCaption ?? "");
            byte[] textBytes = Encoding.Default.GetBytes(messageText ?? "");
            byte[] buffer = new byte[6 + captionBytes.Length + textBytes.Length + 8];
            BitConverter.TryWriteBytes(buffer.AsSpan(0, 2), (ushort)(buffer.Length - 8));
            BitConverter.TryWriteBytes(buffer.AsSpan(2, 2), (ushort)PacketType.MsgTerminateLoader);
            buffer[4] = (byte)captionBytes.Length;
            Array.Copy(captionBytes, 0, buffer, 5, captionBytes.Length);
            buffer[5 + captionBytes.Length] = (byte)textBytes.Length;
            Array.Copy(textBytes, 0, buffer, 6 + captionBytes.Length, textBytes.Length);
            return buffer;
        }

        public class MsgLoaderData
        {
            [Flags]
            public enum LoaderMessage : byte
            {
                MemoryChanged = 1,
                AutoHunting,
                AutoClick,
                ScriptAutoClick,
                AutoHotkey,
                ScriptAutoHotkey,
                ClientFilesScaning,
                SpeedHack,
                FunctionChanged,
                Injectdll,
                InjectCode,
                Aimbot,
                ZoomHack,
                DebuggerPresent,
                SuspendThreads,
                AbnormalOperation,
                ChangeItems,
                ChangeSpellsID,
                ChangeFlags,
                ChangeAction,
            }

            public LoaderMessage Type;
            public byte GuardVersion;
            public string strParam, Conquer, MagicType, MagicEffect, C3_WDB, DLL_Hash, StrRes, Data_Servers;
            public uint dwParam1, dwParam2;

            public MsgLoaderData(byte[] buffer, GuardShield guard)
            {
                if (buffer != null && buffer.Length >= 4 + 1 + 2)
                {
                    if (BitConverter.ToUInt16(buffer, 2) == (ushort)PacketType.MsgLoader)
                    {
                        if (guard != null)
                            guard.HandleBuffer(ref buffer, buffer.Length);
                        using var rdr = new BinaryReader(new MemoryStream(buffer));
                        rdr.BaseStream.Seek(4, SeekOrigin.Current);
                        Type = (LoaderMessage)rdr.ReadByte();
                        if (Type == LoaderMessage.ClientFilesScaning)
                        {
                            Conquer = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            DLL_Hash = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            MagicType = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            MagicEffect = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            StrRes = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            C3_WDB = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            Data_Servers = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            GuardVersion = rdr.ReadByte();
                        }
                        else if (Type > LoaderMessage.AbnormalOperation)
                        {
                            strParam = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                            dwParam1 = rdr.ReadUInt32();
                            dwParam2 = rdr.ReadUInt32();
                        }
                        else
                        {
                            strParam = Encoding.Default.GetString(rdr.ReadBytes(33)).Replace("\0", "");
                        }
                    }
                }
            }
        }

        public class MsgMachineInfoData
        {
            public string MachineName, MacAddress;
            public uint HDSerial;
            public bool VMware, VPSMachine;

            public MsgMachineInfoData(byte[] buffer, GuardShield guard)
            {
                if (buffer != null && BitConverter.ToUInt16(buffer, 2) == (ushort)PacketType.MsgMachineInfo)
                {
                    if (guard != null)
                        guard.HandleBuffer(ref buffer, buffer.Length);

                    using var rdr = new BinaryReader(new MemoryStream(buffer));
                    rdr.BaseStream.Seek(4, SeekOrigin.Current);
                    MacAddress = Encoding.Default.GetString(rdr.ReadBytes(16)).Replace("\0", "");
                    MachineName = Encoding.Default.GetString(rdr.ReadBytes(32)).Replace("\0", "");
                    HDSerial = rdr.ReadUInt32();
                    VMware = rdr.ReadByte() == 1;
                    VPSMachine = rdr.ReadByte() == 1;
                }
            }
        }

        public class MsgOpenedProcessesData
        {
            public enum Type : byte
            {
                Start,
                Insert,
                Finish,
                Start_ProcessQuery,
                Insert_ProcessQuery,
                Finish_ProcessQuery,
            }

            public Type ActionType;
            public List<string> Processes = new List<string>();
            public string strParam, strParam2, StrdwParam1;
            public uint dwParam1, dwParam2, dwParam3;

            public MsgOpenedProcessesData(byte[] buffer, GuardShield guard)
            {
                if (buffer != null && buffer.Length >= 4 + 1 && BitConverter.ToUInt16(buffer, 2) == (ushort)PacketType.MsgOpenedProcesses)
                {
                    if (guard != null)
                        guard.HandleBuffer(ref buffer, buffer.Length);

                    using var rdr = new BinaryReader(new MemoryStream(buffer));
                    rdr.BaseStream.Seek(4, SeekOrigin.Current);
                    var switchType = rdr.ReadByte();
                    if (!Enum.IsDefined(typeof(Type), switchType))
                    {
                        Console.WriteLine($"[MsgLoader] Error Defined OpenedProcesses > ActionType {switchType}");
                        return;
                    }

                    ActionType = (Type)switchType;
                    if (ActionType == Type.Insert)
                    {
                        int count = rdr.ReadUInt16();
                        Processes = new List<string>(count);
                        for (int i = 0; i < count; i++)
                            Processes.Add(Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadUInt16())).Replace("\0", ""));
                    }
                    else if (ActionType == Type.Insert_ProcessQuery)
                    {
                        strParam = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadUInt16())).Replace("\0", "");
                        strParam2 = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadUInt16())).Replace("\0", "");
                        dwParam1 = rdr.ReadUInt32();
                        dwParam2 = rdr.ReadUInt32();
                        dwParam3 = rdr.ReadUInt32();
                        if (dwParam3 > 0)
                            StrdwParam1 = dwParam3.ToString("x");
                    }
                }
            }
        }
    }
}

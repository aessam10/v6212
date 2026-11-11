using System;
using System.Collections.Generic;
using System.Text;

namespace Long.Network
{

    public static class MsgGuardShield
    {
        private static readonly byte[] TkfCyhu9oD8PqWwC = new byte[]
{
        0xDD, 0x97, 0xA6, 0x9B, 0xAE, 0x95, 0x95, 0xD4, 0xA2, 0x9D, 0x81, 0xDD, 0x9E, 0xA2, 0x9A, 0xA3,
        0x9E, 0xBB, 0xBB, 0x9E, 0xA3, 0x9A, 0xB8, 0x79, 0x81, 0x9B, 0x93, 0x9E, 0x9A, 0x79, 0x95, 0xA4,
        0x98, 0x55, 0x72, 0x4A, 0x4D, 0x6F, 0x3E, 0x59, 0x4E, 0x3E, 0x6D, 0x59, 0x79, 0xBB, 0x59, 0x57,
        0x5B, 0x71, 0x6F, 0x7D, 0x42, 0x56, 0x79, 0x2F, 0x79, 0x70, 0x4F, 0x2E, 0x50, 0x25, 0x7C, 0x5B,
        0x2F, 0x16, 0x74, 0x56, 0x54, 0x67, 0x17, 0x75, 0x44, 0x50, 0x63, 0x40, 0x7E, 0x76, 0x47, 0x77,
        0x6B, 0x64, 0x7B, 0x7C, 0x62, 0x72, 0x77, 0x7C, 0x7C, 0x08, 0x53, 0x78, 0x7C, 0x09, 0x44, 0x4A,
        0x02, 0x31, 0x11, 0x11, 0x29, 0x33, 0x1E, 0x14, 0x32, 0x10, 0x2F, 0x0D, 0x2F, 0x1E, 0x23, 0x7F,
        0x7C, 0x18, 0x02, 0x12, 0x12, 0x65, 0x1D, 0x18, 0x2D, 0x16, 0x17, 0x12, 0x0C, 0x17, 0x65, 0x0D
};

        public static void HandleBuffer(ref byte[] buffer, int len)
        {
            if (buffer != null && len > 4 && len <= buffer.Length)
            {
                int useuSMBcoJXnXfNP = 0xDF;

                byte[] swPRPsbTulYMFBeY = new byte[TkfCyhu9oD8PqWwC.Length];
                for (int i = 0; i < TkfCyhu9oD8PqWwC.Length; i++)
                {
                    swPRPsbTulYMFBeY[i] = (byte)(TkfCyhu9oD8PqWwC[i] ^ useuSMBcoJXnXfNP);
                    useuSMBcoJXnXfNP = (useuSMBcoJXnXfNP + 1) % 256;
                }

                for (int i = 0; i < len - 4; i++)
                {
                    buffer[i + 4] ^= swPRPsbTulYMFBeY[i % TkfCyhu9oD8PqWwC.Length];
                }
            }
        }
        public enum PacketIDs : ushort
        {
            MsgAuthentication = 0xDEAD,
            MsgRequestOpenedProcesses,
            MsgOpenedProcesses,
            MsgTerminateLoader,
            MsgLoader,
            MsgRequestMachineInfo,
            MsgMachineInfo,
            MsgLoginGame = 1052,
            PingStatuesLoader,
            MsgRequestScreenPacket,
            MsgScreenPacket,
        }
        public class MsgLoginGame
        {
            public string MachineName, MacAddress, Username, HWID, SecurtyCode, Language;
            public uint Key, AccountHash, HDSerial, OwnerAttackEncrypt, CryptoKey;
            public bool VMware, VPSMachine, ShowHPbar;

            public MsgLoginGame(byte[] Buffer)
            {

                if (Buffer != null)
                {
                    if (BitConverter.ToUInt16(Buffer, 2) == (ushort)PacketIDs.MsgLoginGame)
                    {
                        HandleBuffer(ref Buffer, Buffer.Length);
                        BinaryReader rdr = new BinaryReader(new MemoryStream(Buffer));
                        rdr.BaseStream.Seek(4, SeekOrigin.Current);
                        CryptoKey = rdr.ReadUInt32();
                        if (CryptoKey != 0xF8E44A2)
                            throw new Exception("Invalid buffer Info");
                        Key = rdr.ReadUInt32();
                        AccountHash = rdr.ReadUInt32();
                        MachineName = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        MacAddress = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        Username = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        HWID = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        Language = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        HDSerial = rdr.ReadUInt32();
                        OwnerAttackEncrypt = rdr.ReadUInt32();
                        VMware = rdr.ReadByte() == 1;
                        VPSMachine = rdr.ReadByte() == 1;
                        rdr.Close();
                    }
                }
            }
        }
        
        public class Authentication
        {
     
            public string Username, Password, Server, MacAddress, HWID, SecurtyCode, Language;
            public uint HDSerial, CryptoKey;
            public bool VMware, VPSMachine, AutoLogin;
            public Authentication(byte[] Buffer)
            {
                if (Buffer != null)
                {
                    if (BitConverter.ToUInt16(Buffer, 2) == (ushort)PacketIDs.MsgAuthentication)
                    {
                        HandleBuffer(ref Buffer, Buffer.Length);

                        BinaryReader rdr = new BinaryReader(new MemoryStream(Buffer));
                        rdr.BaseStream.Seek(4, SeekOrigin.Current);
                        CryptoKey = rdr.ReadUInt32();
                        if (CryptoKey != 0xF8E44A2)
                            throw new Exception("Invalid buffer Info");

                        Username = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        Password = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        Server = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        MacAddress = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        HWID = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        Language = Encoding.Default.GetString(rdr.ReadBytes(rdr.ReadByte())).Replace("\0", "");
                        HDSerial = rdr.ReadUInt32();
                        VMware = rdr.ReadByte() == 1;
                        VPSMachine = rdr.ReadByte() == 1;
                        AutoLogin = rdr.ReadByte() == 1;
                        rdr.Close();
                    }
                }
            }
        }
    }
}

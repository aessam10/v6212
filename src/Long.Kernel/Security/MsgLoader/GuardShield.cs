using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Long.Kernel.Network.Game;
using Long.Network.Packets;

namespace Long.Kernel.Security.MsgLoader
{
    public class GuardShield
    {
        private readonly GameClient client;
        public DateTime TaskProcess = DateTime.Now;
        public bool ForceQuery = false;
        public bool RequestProcess = false;

        public GuardShield(GameClient pClient)
        {
            client = pClient;
        }

        public void Disconnect(string reason = null)
        {
            if (!string.IsNullOrEmpty(reason))
                Console.WriteLine($"[GuardShield] KICKOUT Name: {client.Character?.Name ?? "Unknown"}, Reason: {reason}");
            client.Disconnect();
        }

        public async Task TerminateLoaderAsync(string caption = "", string text = "")
        {
            byte[] packet = MsgGuardShield.TerminateLoader(caption, text);
            HandleBuffer(ref packet, packet.Length);
            await client.SendAsync(packet);
        }

        public async Task RequestMachineInfoAsync()
        {
            byte[] packet = MsgGuardShield.RequestMachineInfo();
            HandleBuffer(ref packet, packet.Length);
            await client.SendAsync(packet);
        }

        public async Task RequestOpenedProcessesAsync(MsgGuardShield.MsgOpenedProcessesData.Type type = MsgGuardShield.MsgOpenedProcessesData.Type.Start)
        {
            byte[] packet = MsgGuardShield.RequestOpenedProcesses(type);
            HandleBuffer(ref packet, packet.Length);
            RequestProcess = true;
            await client.SendAsync(packet);
        }

        public async Task PingStatusLoaderAsync(string statusMsg = "")
        {
            byte[] packet = MsgGuardShield.PingStatuesLoader(statusMsg);
            HandleBuffer(ref packet, packet.Length);
            await client.SendAsync(packet);
        }
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
        public void HandleBuffer(ref byte[] buffer, int len)
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
    }
}

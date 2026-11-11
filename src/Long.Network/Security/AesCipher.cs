using System.Security.Cryptography;
using System.Text;

namespace Long.Network.Security
{
    public sealed class AesCipher : ICipher
    {
        public readonly static string SharedKey = "8y/B?E(H+MbQeThWmZq3t6w9z$C&F)J@";
        public readonly static string SharedIv = "t6w9z$C&F)J@NcRf";

        private Aes aes;
        private ICryptoTransform mEncryptor;
        private ICryptoTransform mDecryptor;
        private byte[] mEncryptRegister;
        private byte[] mDecryptRegister;

        private byte[] mEncryptIv;
        private byte[] mDecryptIv;

        private AesCipher()
        {
        }

        [Obsolete("Do not use this method with shared keys or change the Shared Keys to private ones.", false)]
        public static AesCipher Create()
        {
            return Create(SharedKey, SharedIv, SharedIv);
        }

        public static AesCipher Create(string key, string eIv, string dIv)
        {
            var cipher = new AesCipher
            {
                aes = Aes.Create()
            };

            cipher.aes.Mode = CipherMode.CFB;
            cipher.aes.KeySize = 256;
            cipher.aes.BlockSize = 128;
            cipher.aes.FeedbackSize = 8;
            cipher.aes.Padding = PaddingMode.None;

            cipher.aes.Key = Convert.FromBase64String(key);
            cipher.mEncryptIv = Convert.FromBase64String(eIv);
            cipher.mDecryptIv = Convert.FromBase64String(dIv);

            cipher.ResetStreams();
            return cipher;
        }

        /// <inheritdoc />
        public void GenerateKeys(params object[] seeds)
        {
            byte[] key = (byte[])seeds[0];
            key.CopyTo(new Memory<byte>(aes.Key));

            if (seeds.Length > 2)
            {
                byte[] eIv = (byte[])seeds[1];
                byte[] dIv = (byte[])seeds[2];
                eIv.CopyTo(new Memory<byte>(mEncryptIv));
                dIv.CopyTo(new Memory<byte>(mDecryptIv));
            }
            else
            {
                Console.WriteLine($"Using shared encryption settings!!! Not recommended on production environment");

                byte[] iv = Encoding.ASCII.GetBytes(SharedIv);

                mEncryptIv = new byte[iv.Length];
                mDecryptIv = new byte[iv.Length];

                iv.CopyTo(mEncryptIv, 0);
                iv.CopyTo(mDecryptIv, 0);
            }

            ResetStreams();
        }

        /// <summary>
        ///     CFB-8 by hand, each direction keeps its register for the whole connection. TCP can join two packets
        ///     in one receive or split one, so going back to the IV on every call breaks the packet after the first.
        /// </summary>
        private void ResetStreams()
        {
            using Aes block = Aes.Create();
            block.Mode = CipherMode.ECB;
            block.Padding = PaddingMode.None;
            block.Key = aes.Key;

            mEncryptor = block.CreateEncryptor();
            mDecryptor = block.CreateEncryptor();
            mEncryptRegister = (byte[])mEncryptIv.Clone();
            mDecryptRegister = (byte[])mDecryptIv.Clone();
        }

        /// <inheritdoc />
        public void Decrypt(Span<byte> src, Span<byte> dst)
        {
            byte[] block = new byte[mDecryptRegister.Length];
            for (var i = 0; i < src.Length; i++)
            {
                mDecryptor.TransformBlock(mDecryptRegister, 0, mDecryptRegister.Length, block, 0);
                byte cipherByte = src[i];
                dst[i] = (byte)(cipherByte ^ block[0]);
                Shift(mDecryptRegister, cipherByte);
            }
        }

        /// <inheritdoc />
        public void Encrypt(Span<byte> src, Span<byte> dst)
        {
            byte[] block = new byte[mEncryptRegister.Length];
            for (var i = 0; i < src.Length; i++)
            {
                mEncryptor.TransformBlock(mEncryptRegister, 0, mEncryptRegister.Length, block, 0);
                var cipherByte = (byte)(src[i] ^ block[0]);
                dst[i] = cipherByte;
                Shift(mEncryptRegister, cipherByte);
            }
        }

        private static void Shift(byte[] register, byte value)
        {
            Buffer.BlockCopy(register, 1, register, 0, register.Length - 1);
            register[^1] = value;
        }

        public class Settings
        {
            public string Key { get; set; }
            public string EncryptIV { get; set; }
            public string DecryptIV { get; set; }
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES256Sharp
{
    public static class AES256
    {
        private static string GenerateSaltKey(string password)
        {
            Rfc2898DeriveBytes rfc2898db = new Rfc2898DeriveBytes(password, 16, 10000);

            byte[] data = new byte[48];
            Buffer.BlockCopy(rfc2898db.Salt, 0, data, 0, 16);
            Buffer.BlockCopy(rfc2898db.GetBytes(32), 0, data, 16, 32);
            return Convert.ToBase64String(data);
        }

        private static byte[] GenerateKey(string password, byte[] salt)
        {
            Rfc2898DeriveBytes rfc2898db = new Rfc2898DeriveBytes(password, salt, 10000);
            return rfc2898db.GetBytes(32);
        }

        public static string Encrypt(string plain, string password)
        {
            if (plain == null || plain.Length == 0) return null;

            byte[] encrypted;
            byte[] data = Encoding.UTF8.GetBytes(plain);

            string saltKeyStr = GenerateSaltKey(password);
            byte[] saltKeyB = Convert.FromBase64String(saltKeyStr);
            byte[] salt = new byte[16];
            byte[] key = new byte[32];
            Buffer.BlockCopy(saltKeyB, 0, salt, 0, 16);
            Buffer.BlockCopy(saltKeyB, 16, key, 0, 32);
            saltKeyStr = null;
            saltKeyB = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesCryptoServiceProvider aes256 = new AesCryptoServiceProvider())
                {
                    aes256.KeySize = 256;
                    aes256.BlockSize = 128;
                    aes256.GenerateIV();
                    aes256.Padding = PaddingMode.PKCS7;
                    aes256.Mode = CipherMode.CBC;
                    aes256.Key = key;
                    key = null;

                    using (CryptoStream cs = new CryptoStream(ms, aes256.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        ms.Write(aes256.IV, 0, aes256.IV.Length);
                        ms.Write(salt, 0, 16);
                        cs.Write(data, 0, plain.Length);
                    }
                }

                encrypted = ms.ToArray();
            }

            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt(string cipher, string password)
        {
            if (cipher == null || cipher.Length == 0) return null;

            byte[] decrypted;
            byte[] data = Convert.FromBase64String(cipher);

            using (MemoryStream ms = new MemoryStream(data))
            {
                using (AesCryptoServiceProvider aes256 = new AesCryptoServiceProvider())
                {
                    byte[] iv = new byte[16];
                    byte[] salt = new byte[16];
                    ms.Read(iv, 0, 16);
                    ms.Read(salt, 0, 16);

                    aes256.KeySize = 256;
                    aes256.BlockSize = 128;
                    aes256.IV = iv;
                    aes256.Padding = PaddingMode.PKCS7;
                    aes256.Mode = CipherMode.CBC;
                    aes256.Key = GenerateKey(password, salt);

                    using (var cs = new CryptoStream(ms, aes256.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        byte[] temp = new byte[ms.Length - 16 - 16 + 1];
                        decrypted = new byte[cs.Read(temp, 0, temp.Length)];
                        Buffer.BlockCopy(temp, 0, decrypted, 0, decrypted.Length);
                    }
                }
            }

            return Encoding.UTF8.GetString(decrypted);
        }
    }
}

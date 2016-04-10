using System.Security.Cryptography;
using System.Text;

namespace AES256Sharp
{
    public static class SHA256
    {
        public static string GenerateHash(string text)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
            {
                data = sha.ComputeHash(data);
            }

            StringBuilder hash = new StringBuilder();

            foreach (byte _byte in data)
                hash.Append(_byte.ToString("x2"));

            return hash.ToString();
        }

        public static byte[] GenerateHash(byte[] data)
        {
            using (SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider())
            {
                data = sha.ComputeHash(data, 0, data.Length);
            }

            return data;
        }
    }
}

/*
AES256 - AES 256 encryption using CryptoAPI
Copyright (C) 2016  @maldevel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

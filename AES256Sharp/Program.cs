using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AES256Sharp
{
    class Program
    {
        static void Main(string[] args)
        {
            string password = "c4XgnRwfNeD7vybM7pEX";
            string encrypted = AES256.Encrypt("testing", password);
            string decrypted = AES256.Decrypt(encrypted, password);

            Console.WriteLine("Encrypted text: " + encrypted);
            Console.WriteLine("Decrypted text: " + decrypted);
        }
    }
}

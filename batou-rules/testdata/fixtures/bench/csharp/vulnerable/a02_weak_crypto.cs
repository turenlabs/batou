// Source: CWE-327 - Use of weak MD5 hash in C#
// Expected: BATOU-CRY
// OWASP: A02:2021 - Cryptographic Failures

using System;
using System.Security.Cryptography;
using System.Text;

namespace App
{
    class CryptoHelper
    {
        public string HashPassword(string password)
        {
            using (var md5 = MD5.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(password);
                var hash = md5.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        static void Main()
        {
            var helper = new CryptoHelper();
            Console.WriteLine(helper.HashPassword("admin123"));
        }
    }
}

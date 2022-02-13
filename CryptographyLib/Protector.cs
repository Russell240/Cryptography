using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Principal;
using System.IO; 
using System.Xml.Linq;
using CryptographyLib;

namespace CryptographyLib
{
    public static class Protector
    {
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7 bytes");
        private static readonly int iterations = 20;
        public static string Encrypt(string plaintext, string password)
        {
            byte[] encryptedBytes;
            byte[] plainBytes = Encoding.Unicode.GetBytes(plaintext);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                }
                encryptedBytes = ms.ToArray();
            }
            return Convert.ToBase64String(encryptedBytes);
        }
        public static string Decrypt(string cryptotext, string password)
        {
            byte[] plainbytes;
            byte[] cryptobytes = Convert.FromBase64String(cryptotext);
            var aes = Aes.Create();
            var pdkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pdkdf2.GetBytes(32);
            aes.IV = pdkdf2.GetBytes(16);
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cryptobytes, 0, cryptobytes.Length);
                }
                plainbytes = ms.ToArray();
            }
            return Encoding.Unicode.GetString(plainbytes);

        }

        private static Dictionary<String, User> Users =
            new Dictionary<String, User>();
        public static User Register(string username, string password)
        {
            var rng = RandomNumberGenerator.Create();
            var saltbtyes = new byte[16];
            rng.GetBytes(saltbtyes);
            var saltext = Convert.ToBase64String(saltbtyes);
            var saltedhashedPassword = SaltAndHashPassword(password, saltext);
            var user = new User
            {
                Name = username,
                Salt = saltext,
                SaltedHashedPassword = saltedhashedPassword,
            };
            Users.Add(user.Name, user);
            return user;
        }

        public static bool checkPassword(string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }
            var user = Users[username];
            var saltedhashedpassword= SaltAndHashPassword(password, user.Salt);
            return (saltedhashedpassword == user.SaltedHashedPassword);

        }

        private static string SaltAndHashPassword(string password, string salt)
        {
            var sha = SHA256.Create();
            var saltedpassword = password + salt;
            return Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedpassword)));
        }
    }
}

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
        public static User Register(string username, string password, string []roles= null)
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
                Roles= roles, 
            };
            Users.Add(user.Name, user);
            return user;
        }

        public static bool CheckPassword(string username, string password)
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
        public static string PublicKey;
        public static string ToXmlStringExt(this RSA rsa,bool includePrivateParameters ) 
        {
            var p = rsa.ExportParameters(includePrivateParameters);
            XElement xml;
            if (includePrivateParameters) 
            {
                xml = new XElement("RSA value",
                    new XElement("Modulus", Convert.ToBase64String(p.Modulus)),
                    new XElement("Exponent", Convert.ToBase64String(p.Exponent)),
                    new XElement("P", Convert.ToBase64String(p.P)),
                    new XElement("Q", Convert.ToBase64String(p.Q)),
                    new XElement("DP", Convert.ToBase64String(p.DP)),
                    new XElement("DQ", Convert.ToBase64String(p.DQ)),
                    new XElement("InverseQ", Convert.ToBase64String(p.InverseQ))
                    );
             }
            else 
            {
                xml = new XElement("RSAKeyValue",
                    new XElement("Modulus", Convert.ToBase64String(p.Modulus)),
                    new XElement("Expontent", Convert.ToBase64String(p.Exponent)));
                    ;
            }
            return xml ?.ToString();
            }
        public static void FromXmlStringExt(this RSA rsa,string paramtersAsXml ) 
        {
            var xml = XDocument.Parse(paramtersAsXml);
            var root = xml.Element("RSAKeyValue");
            var p = new RSAParameters
            {
                Modulus= Convert.FromBase64String(root.Element("Modulus" ).Value),
                Exponent= Convert.FromBase64String(root.Element("Exponent").Value)

            };
            if (root.Element("P") != null) 
            {
                p.Q = Convert.FromBase64String(root.Element("P").Value);
                p.Q = Convert.FromBase64String(root.Element("Q").Value);
                p.DP = Convert.FromBase64String(root.Element("DP").Value);
                p.InverseQ = Convert.FromBase64String(root.Element("InverseQ").Value);
                rsa.ImportParameters(p);

            }
        }
        public static string GenerateSignature(string data) 
        {
            byte[] dataBytes = Encoding.Unicode.GetBytes(data);
            var sha = SHA256.Create();
            var hasheddata = sha.ComputeHash(dataBytes);
            var rsa = RSA.Create();
            PublicKey = rsa.ToXmlString(false);
            return Convert.ToBase64String(rsa.SignHash(hasheddata,
                HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1 ));
        }

        public static bool ValidateSignature(string data, string signature) 
        {
            byte[] dataBytes = Encoding.Unicode.GetBytes(data);
            var sha = SHA256.Create();
            var hasheddata = sha.ComputeHash(dataBytes);
            byte[] signatureBytes =Convert.FromBase64String(signature);
            var rsa = RSA.Create();
            rsa.FromXmlString(PublicKey);
            return rsa.VerifyHash(hasheddata, signatureBytes,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static byte[] GetRandomKeyOrIV(int size)
        {
            var r = RandomNumberGenerator.Create();
            var data = new byte[size];
            r.GetNonZeroBytes(data);
            // data is filled with random bytes
            return data;
        }

        public static void LogIn(string username, string password) 
        {
            if (CheckPassword(username, password))
            {
                var identity = new GenericIdentity(username, "PackAuth");
                var principal = new GenericPrincipal(identity,Users[username].Roles);
                System.Threading.Thread.CurrentPrincipal = principal;


            }
        }
    }

}


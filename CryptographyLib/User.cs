using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyLib
{
    public class User 
    {
      
        public string Name { get; set;  }
        public string Salt { get; set; }

        public string SaltedHashedPassword { get; set; }

        private static Dictionary<string, User> Users = new Dictionary<string,User>();
        public static User Register(string username, string password ) 
        {
            var rng = RandomNumberGenerator.Create();
            var saltbytes = new byte[16];
            rng.GetBytes(saltbytes);
            var saltext = Convert.ToBase64String(saltbytes);
            var saltedHashedPassword = SaltAndHashPassword(password, saltext);
            var user = new User
            {
                Name = username, Salt = saltext, SaltedHashedPassword = saltedHashedPassword
            };
            Users.Add(user.Name, user);
            return user; 
        }

        private static string SaltAndHashPassword(string password, string salt ) 
        {
            var sha = SHA256.Create();
            var saltedpassword = password + salt;
            return Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedpassword)));
        }

       
    }
}
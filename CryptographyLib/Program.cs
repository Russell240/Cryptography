
using System.Security.Cryptography;
using static System.Console;
using System;
using System.Threading;
using System.Security;

namespace CryptographyLib
{
    class Program 
    {
        static void Main(string[] args)
        {
            Write("Enter a message you want to encrypt: ");
            string message = Console.ReadLine();
            Write("Enter a password:  ");
            string password = Console.ReadLine();
            string cryptoText = Protector.Encrypt(message, password);
            WriteLine($"Encrypted text: {cryptoText}");
            Write("Enter the password:" );
            string password2 = Console.ReadLine();
            try
            {
                string cleartext = Protector.Decrypt(cryptoText, password);
                WriteLine($"Decrypted text : { cleartext}");
            }
            catch (CryptographicException ex)
            {
                WriteLine("{0}\n More Details {1}", arg0: "You entered the wrong password ", arg1: ex.Message);
            }
            catch (Exception ex) 
            {
               WriteLine("Non cryptographic exception: {0}, {1} ", arg0: ex.GetType().Name, arg1: ex.Message);
            }
        }

        static void SecureFeature() 
        {
            if (Thread.CurrentPrincipal == null) 
            {
                throw new SystemException("A user must be logged into to access " +
                    "this feature ");
            }
            if (!Thread.CurrentPrincipal.IsInRole("Admins")) 
            {
                throw new SecurityException("User must be a " +
                    "member of the admins to access this feature");

             }
            Console.WriteLine("You have access to this security features ");

        }
    }
}

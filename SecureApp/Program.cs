using System;
using System.Security;
using System.Security.Principal;
using System.Threading;
using System.Security.Permissions;
using CryptographyLib;

namespace SecureApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Protector.Register("Alice","Pa$$word", new[] { "Admins" });
            Protector.Register("Bob", "Pa$$word", new[] {"Sales", "TeamLeads" });
            Protector.Register("Eve", "Pa$$word");
            Console.Write($"Enter your username ");
            string username = Console.ReadLine();
            Console.Write($"Enter your password ");
            string password = Console.ReadLine();
            Protector.LogIn(username, password);
            if (Thread.CurrentPrincipal==null) 
            {
                Console.WriteLine("Login Failed");
                return;
            }
            var p = Thread.CurrentPrincipal;
            Console.WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated} ");
            Console.WriteLine($"", );
        }
    }
}

using System;
using System.Security;
using System.Security.Principal;
using System.Threading;
using System.Security.Permissions;
using CryptographyLib;
using System.Security.Claims;

namespace SecureApp
{
    class Program
    {
        Program program = new Program();
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
                Console.WriteLine("Login Failed please try again ");
                return;
            }
            var p = Thread.CurrentPrincipal;
            Console.WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated} ");
            Console.WriteLine($"Name { p.Identity.Name}");
            Console.WriteLine($"IsRole(\"Admins\") : {p.IsInRole("Admins")}");
            Console.WriteLine($"IsRole(\"Sales\"): {p.IsInRole("Sales")} ");
            if (p is ClaimsPrincipal) 
            {
                Console.WriteLine($"{p.Identity} has the following claims ");

                foreach (Claim  claim in (p as ClaimsPrincipal).Claims) 
                {
                    Console.WriteLine($"{claim.Type}:{claim.Value} "); 
                }
            }

            try
            {
                Program.SecureFeature();
            }
            catch 
            { 

            }
        }
    }
}

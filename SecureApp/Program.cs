using System;
using System.Security;
using System.Security.Principal;
using System.Threading;
using System.Security.Permissions;
using CryptographyLib;
using static System.Console;
using System.Security.Claims;

namespace SecureApp
{
    class Program
    {
         static void Main(string[] args)
        {
            Protector.Register("Alice","Pa$$word", new[] { "Admins" });
            Protector.Register("Bob", "Pa$$word", new[] {"Sales", "TeamLeads" });
            Protector.Register("Eve", "Pa$$word");
            Write($"Enter your username ");
            string username = Console.ReadLine();
            Write($"Enter your password ");
            string password = Console.ReadLine();
            Protector.LogIn(username, password);
            if (Thread.CurrentPrincipal==null) 
            {
                Console.WriteLine("Login Failed please try again ");
                return;
            }
            var p = Thread.CurrentPrincipal;
            WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated} ");
            WriteLine($"Name { p.Identity.Name}");
            WriteLine($"IsRole(\"Admins\") : {p.IsInRole("Admins")}");
            WriteLine($"IsRole(\"Sales\"): {p.IsInRole("Sales")} ");
            if (p is ClaimsPrincipal) 
            {
               WriteLine($"{p.Identity} has the following claims ");

                foreach (Claim  claim in (p as ClaimsPrincipal).Claims) 
                {
                    WriteLine($"{claim.Type}:{claim.Value} "); 
                }
            }

            try
            {
                SecureFeature();
            }
            catch(System.Exception ex )
            {
                WriteLine($"{ex.GetType()}:{ex.Message}");
            }
        }

        // method checks for correct user access rights 
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
            WriteLine("You have access to this security features ");

        }
    }
}

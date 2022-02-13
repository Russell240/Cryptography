using CryptographyLib;
using static System.Console;


namespace HashingApp
{
    class Program
    {
        static void Main(string[] args)
        {
            WriteLine("Hello World!");
            WriteLine("Registering Alice with Pa$$word ");
            var alice = Protector.Register("Alice", "Pa$$word");
            WriteLine($"Name:{alice:Name}");
            WriteLine($"Salt:{alice:Salt}");
            WriteLine("Password (salted and hashed) : {0}", 
                arg0: alice.SaltedHashedPassword);
            WriteLine();
            Write("Enter a new user register ");
            string username = ReadLine();
            Write($"Enter a password for {username}: ");
            string password = ReadLine();
            var user = Protector.Register(username, password);
            WriteLine($"Name : {user.Name}");
            WriteLine($"Password: (salted and hashed) {0}", arg0
                : user.SaltedHashedPassword);
            WriteLine();
            bool correctPassword = false;
            while (!correctPassword) 
            {
                Write("Enter a username to log in ");
                string loginUsername = ReadLine();
                Write("Enter a password to login in");
                string loginpassword = ReadLine();
                correctPassword = Protector.checkPassword(loginUsername, loginpassword);
                if (correctPassword)
                {
                    WriteLine($"Correct! {loginUsername} has been logged in ");

                }
                else 
                {
                    WriteLine("Invalid Password ! Enter login credentials again ");
                }


            }


        }
    }
}

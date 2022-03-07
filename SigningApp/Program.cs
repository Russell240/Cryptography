using System;
using CryptographyLib;

namespace SigningApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            string data = Console.ReadLine();
            var signature = Protector.GenerateSignature(data);
            Console.WriteLine($"Signature :{signature}");
            Console.WriteLine("protector", Protector.PublicKey);
        }
    }
}

using CryptographyLib;
using System;
namespace RandomizingApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("How Big do you want the key in the bytes ");
            string size = Console.ReadLine();
            byte[] key = Protector.GetRandomKeyOrIV(int.Parse(size));
            Console.WriteLine($"Key as byte array");
            for (int b = 0; b < key.Length; b++) 
            {
                Console.WriteLine($"{key[b]:x2}");
                if (((b + 1) % 16) == 0) Console.WriteLine();
            }

        }
    }
}

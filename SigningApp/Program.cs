using System;
using CryptographyLib;

namespace SigningApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter some text");
            string data = Console.ReadLine();
            var signature = Protector.GenerateSignature(data);
            Console.WriteLine($"Signature :{signature}");
            Console.WriteLine("protector", Protector.PublicKey);
            if (Protector.ValidateSignature(data, signature))
            {
                Console.WriteLine("Correct! Signature is valid ");
            }
            else 
            {
                Console.WriteLine("Invalid Signature ");
            }
            //simulate a fake signature by replacing the first character with an x 
            var fakeSignature = signature.Replace(signature[0],'X');
            if (Protector.ValidateSignature(data, fakeSignature))
            {
                Console.WriteLine("Correct! Singature is valid");
            }
            else 
            {
                Console.WriteLine($"Invalid Signature: {fakeSignature}");
            }

        }


    }
}

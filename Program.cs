using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PwnedPasswordChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = "";
            string sha1pw = "";
            Console.WriteLine("Pwned Password Checker in C#\r");
            Console.WriteLine("----------------------------\n");

            do
            {
                Console.WriteLine("Enter the password you want to check and press Enter.");
                input = Convert.ToString(Console.ReadLine());
            } while (!IsASCII(input));

            sha1pw = GetSha1HashString(input);
            Console.WriteLine($"SHA-1:{sha1pw}");

            // Split into first 5 bytes and subsequent 6 bytes
            string[] pwArr = SplitStr(sha1pw, 5);

            // Call PwnedPasswordAPI with first 5 bytes
            if (IsPwnedPassword(pwArr[0], pwArr[1]))
            {
                Console.WriteLine("The password you entered may have been pwned, so consider a different password.");
            }
            else
            {
                Console.WriteLine("The password you entered has not been pwned.");
            }
        }

        private static bool IsASCII(string target)
        {
            return new Regex("^[\x20-\x7E]+$").IsMatch(target);
        }

        private static string GetSha1HashString(string target)
        {
            // Convert a string to an array of bytes
            byte[] data = Encoding.UTF8.GetBytes(target);

            // SHA-1 hash algorithm generation
            var sha1Algorithm = new SHA1CryptoServiceProvider();

            // Calculate the hash value
            byte[] bs = sha1Algorithm.ComputeHash(data);

            // Release resources
            sha1Algorithm.Clear();

            // Convert a byte array to a hexadecimal string
            var result = new StringBuilder();
            foreach (byte b in bs)
            {
                result.Append(b.ToString("X2"));
            }
            return result.ToString();
        }

        private static string[] SplitStr(string target, int i)
        {
            string[] output = new string[2];
            output[0] = target.Substring(0, i);
            output[1] = target.Substring(i);
            return output;
        }

        private static bool IsPwnedPassword(string pwFront, string pwBack)
        {
            string url = $"https://api.pwnedpasswords.com/range/{pwFront}";
            string line;
            Console.WriteLine($"URL:{url}");

            // Call PwnedPasswordAPI
            WebRequest request = WebRequest.Create(url);
            Stream response_stream = request.GetResponse().GetResponseStream();
            StreamReader reader = new StreamReader(response_stream);
            while ((line = reader.ReadLine()) != null)
            {
                // Compare the hash value returned by the API with the input hash value
                if (line.Substring(0,35) == pwBack)
                {
                    // Return True because there is a match
                    Console.WriteLine(line);
                    return true;
                }
            }
            return false;
        }
    }
}

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            //var emp = new object()
            //{
            //    Id = 100,
            //    Hash = "indore"
            //};
            string statext = "senha";
            object[] emp = {
            new object [] {"MetaDataCollections", 0, 0}
            };
            //byte[] data;
            //BinaryFormatter bf = new BinaryFormatter();
            //MemoryStream ms = new MemoryStream();
            //bf.Serialize(ms, emp);

            //data = ms.ToArray();
            byte[] data = ObjectToByteArray(emp);

            string ob = SHA512(data);

            //HMACSHA512 hmac = new HMACSHA512(data);

            //byte[] storedHash = new byte[hmac.HashSize / 8];

            string sha = SHA512(statext).Substring(1,35);

            Console.WriteLine(sha);
        }

        public static string SHA512(string input)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            using (var hash = System.Security.Cryptography.SHA512.Create())
            {
                var hashedInputBytes = hash.ComputeHash(bytes);

                // Convert to text
                // StringBuilder Capacity is 128, because 512 bits / 8 bits in byte * 2 symbols for byte 
                var hashedInputStringBuilder = new System.Text.StringBuilder(128);
                foreach (var b in hashedInputBytes)
                    hashedInputStringBuilder.Append(b.ToString("X2"));
                return hashedInputStringBuilder.ToString();
            }
        }

        public static string SHA512(byte[] input)
        {
            //var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            using (var hash = System.Security.Cryptography.SHA512.Create())
            {
                var hashedInputBytes = hash.ComputeHash(input);

                // Convert to text
                // StringBuilder Capacity is 128, because 512 bits / 8 bits in byte * 2 symbols for byte 
                var hashedInputStringBuilder = new System.Text.StringBuilder(128);
                foreach (var b in hashedInputBytes)
                    hashedInputStringBuilder.Append(b.ToString("X2"));
                return hashedInputStringBuilder.ToString();
            }
        }


        public class TxId
        {
            public int Id { get; set; }
            public string Hash { get; set; }
        };

        public static byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
            {
                return null;
            }
            var bf = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }

        public static byte[] HmacSha512(string text, string key)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);

            var hmac = new HMac(new Org.BouncyCastle.Crypto.Digests.Sha512Digest());
            hmac.Init(new KeyParameter(System.Text.Encoding.UTF8.GetBytes(key)));

            byte[] result = new byte[hmac.GetMacSize()];
            hmac.BlockUpdate(bytes, 0, bytes.Length);
            hmac.DoFinal(result, 0);

            return result;
        }
    }
}

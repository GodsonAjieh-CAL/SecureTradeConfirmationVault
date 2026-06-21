using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace SecureTradeConfirmationVault
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string tradeconfirm1 = "TR001|Apex|15000|GBP";
            string tradeconfirm2 = "TR002|Newton|22000|USD";

            byte[] encode = Encoding.UTF8.GetBytes(tradeconfirm1);
            byte[] hashedTrade = SHA256.HashData(encode);

            string hexTrade = Convert.ToHexString(hashedTrade);
            Console.WriteLine(hexTrade);

            string tamperedConfirm = "TR001|Apex|15000|USD";
            byte[] tamperedEncode = Encoding.UTF8.GetBytes(tamperedConfirm);
            byte[] tamperedHashedTrade = SHA256.HashData(tamperedEncode);

            string tamperedHexTrade = Convert.ToHexString(tamperedHashedTrade);
            Console.WriteLine(tamperedHexTrade);

            byte[] key;
            byte[] iV;
            byte[] ciphertext;
            byte[] ciphertext2;

            using (Aes aes = Aes.Create()) //you get instance of Aes from the factory method
            {
                aes.GenerateKey();
                aes.GenerateIV();

                key = aes.Key;
                iV = aes.IV;

                using (ICryptoTransform cryptoTransform = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(tradeconfirm1);
                    using (CryptoStream cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        // ms.Write(hashedTrade); this isnt writing to the cryptoStream
                        cryptoStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    ciphertext = ms.ToArray();
                    string cipherBase64 = Convert.ToBase64String(ciphertext);
                    Console.WriteLine(cipherBase64);
                }

                using (ICryptoTransform cryptoTransform2 = aes.CreateEncryptor())
                using (MemoryStream ms2 = new MemoryStream())
                {
                    byte[] plaintextBytes2 = Encoding.UTF8.GetBytes(tradeconfirm2);
                    using (CryptoStream cryptoStream = new CryptoStream(ms2, cryptoTransform2, CryptoStreamMode.Write))
                    {
                        // ms.Write(hashedTrade); this isnt writing to the cryptoStream
                        cryptoStream.Write(plaintextBytes2, 0, plaintextBytes2.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    ciphertext2 = ms2.ToArray();
                    string cipherBase64 = Convert.ToBase64String(ciphertext2);
                    Console.WriteLine(cipherBase64);
                }
            }


            using (Aes aes = Aes.Create())
            {
                //key and IV retrieved here
                aes.Key = key;
                aes.IV = iV;

                using (ICryptoTransform cryptoDecrypt = aes.CreateDecryptor())
                using (MemoryStream vault = new MemoryStream(ciphertext))
                using (CryptoStream cryptoStream = new CryptoStream(vault, cryptoDecrypt, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        string decrypted = reader.ReadToEnd();
                        Console.WriteLine(decrypted);
                        Console.WriteLine(decrypted == tradeconfirm1);
                    }
                }

                using (ICryptoTransform cryptoDecrypt2 = aes.CreateDecryptor())
                using (MemoryStream vault = new MemoryStream(ciphertext2))
                using (CryptoStream cryptoStream2 = new CryptoStream(vault, cryptoDecrypt2, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cryptoStream2))
                    {
                        string decrypted2 = reader.ReadToEnd();
                        Console.WriteLine(decrypted2);
                        Console.WriteLine(decrypted2 == tradeconfirm2);
                    }
                }
            }

            bool result = VerifyIntegrity(tradeconfirm1, hexTrade);
            Console.WriteLine(result ? "Proved it matches" : "Does NOT match its original hash");

            bool matchesTampered = VerifyIntegrity(tradeconfirm1, tamperedHexTrade);
            Console.WriteLine(matchesTampered ? "Proved it matches" : "Does NOT match its original hash");
        }

        public static bool VerifyIntegrity(string original, string hashToCheck)
        {

            byte[] encodeOriginal = Encoding.UTF8.GetBytes(original);
            byte[] hashedOriginal = SHA256.HashData(encodeOriginal);

            string hexOriginal = Convert.ToHexString(hashedOriginal);

            return hexOriginal.Equals(hashToCheck);

            /* No need to hash again then compare
            
            byte[] tamperedHashToCheck = Encoding.UTF8.GetBytes(hashToCheck);
            byte[] tamperedHashedTrade = SHA256.HashData(tamperedHashToCheck);

            string tamperedHexTrade = Convert.ToHexString(tamperedHashedTrade);

            int result = hexOriginal.CompareTo(tamperedHexTrade);
            if (result != 0)
            {
                return false;
            }
            return true; */
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Text;
namespace CSharpGCM
{
    class Program
    {
        static byte[] key;

        static void GCM_Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData)
        {
            using (var gcm = new AesGcm(key))
            {
                gcm.Encrypt(
                    nonce, 
                    plaintext, 
                    ciphertext, 
                    tag, 
                    associatedData);
            }
        }
        static void GCM_Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData)
        {
            using (AesGcm aesGcm = new AesGcm(key))
            {
                aesGcm.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext,
                    associatedData
                    );
            }
        }
        static void ShowBytes(byte[] data)
        {
            foreach (var item in data)
            {
                Console.Write("{0:X}", item);
                Console.Write('-');
            }
            Console.Write('\n');
            Console.Write('\n');
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Input Any Key to run!");
            string password = "18EB38984D82477B992F3F6BF27E8B67";
            key = Encoding.ASCII.GetBytes(password);
            string text = "This is Test Message 01\n";
            Console.WriteLine("Message:" + text + ", size: " + text.Length);
            var data = Encoding.ASCII.GetBytes(text);
            Console.WriteLine("key");
            ShowBytes(key);

            var nonceBytes = new byte[12];
            Array.Copy(key, nonceBytes, 12);
            Console.WriteLine("nonceBytes");
            ShowBytes(nonceBytes);

            var dateTime = DateTime.UtcNow;
            Console.WriteLine("DateTime Binary:" + dateTime.ToBinary().ToString());
            var timeBytes = BitConverter.GetBytes(dateTime.ToBinary());
            Console.WriteLine("timeBytes");
            ShowBytes(timeBytes);

            byte[] EncryptData = new byte[data.Length];
            byte[] DecryptData = new byte[data.Length];
            byte[] tagData = new byte[16];

            GCM_Encrypt(nonceBytes, data, EncryptData, tagData, timeBytes);
            Console.WriteLine("EncryptData");
            ShowBytes(EncryptData);
            Console.WriteLine("tagData");
            ShowBytes(tagData);

            GCM_Decrypt(nonceBytes, EncryptData, tagData, DecryptData, timeBytes);
            Console.WriteLine("DecryptData");
            ShowBytes(DecryptData);

            string decMessage = Encoding.ASCII.GetString(DecryptData);
            Console.WriteLine("DecMessage: " + decMessage  + ";size: " + decMessage.Length);
        }
    }
}

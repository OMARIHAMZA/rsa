using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            RSA.RSAKey.PublicKey publicKey = new RSA.RSAKey.PublicKey(new BigInteger(71),
                new BigInteger(7190949861345235519));

            RSA.RSAKey.PrivateKey privateKey = new RSA.RSAKey.PrivateKey(new BigInteger(5165330178205931231),
                new BigInteger(7190949861345235519));

            RSA.RSAKey rsaKey = new RSA.RSAKey(publicKey, privateKey);
            String result = "5484607733988745964 5187415759615401251 2806422690903320382 2806422690903320382 4381553225247307856 1833280318119474767 1250311601867062333 2193676175874028337 1833280318119474767 1842342604151443977 5169069955531530187 3713042964661203351 5187415759615401251 1833280318119474767 5905418644038832967 2839768042594947994 1833280318119474767 5598297248400419844 5169069955531530187 3713042964661203351 1047249515957844920 5169069955531530187";
            String decrypted = RSA.Decrypt(result, rsaKey);
            Console.WriteLine("Encrypted: " + result);
            Console.WriteLine("Decrypted: " + decrypted);

            System.Console.Read();
        }
    }



    

    class RSA
    {

        public static String Encrypt(String message, RSAKey key)
        {
            if (message == null || key == null) return null;
            StringBuilder result = new StringBuilder();
            for(int i = 0; i<message.Length; i++)
            {
                BigInteger value = new BigInteger((int)message[i]);
                BigInteger cipher = BigInteger.ModPow(value, key.publicKey.e, key.publicKey.n);
                result.Append(cipher + " ");
            }

            return result.ToString();
        }


        public static String Decrypt(String message, RSAKey key)
        {
            if (message == null || key == null) return null;
            StringBuilder result = new StringBuilder();
            String[] values = message.Split(null);
            foreach(String value in values){
                BigInteger val = new BigInteger();
                if (BigInteger.TryParse(value,out val))
                {
                    BigInteger plainValue = BigInteger.ModPow(val, key.privateKey.d, key.privateKey.n);
                    result.Append(Convert.ToChar(((int)plainValue)));
                }
            }
            return result.ToString();
        }

        public class RSAKey
        {

            public PublicKey publicKey;
            public PrivateKey privateKey;


            public RSAKey(PublicKey publicKey, PrivateKey privateKey)
            {
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            }

            public class PublicKey
            {
                 public BigInteger e, n;

                public PublicKey(BigInteger e, BigInteger n)
                {
                    this.e = e;
                    this.n = n;
                }
            }
            
            public class PrivateKey
            {
                public BigInteger d, n;

                public PrivateKey(BigInteger d, BigInteger n)
                {
                    this.d = d;
                    this.n = n;
                }
            }
        }
    }
}

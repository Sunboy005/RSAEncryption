using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace RSAEncryption.Services
{
    public class RsaService
    {
        private static RSACryptoServiceProvider _privateKey;
        private static RSACryptoServiceProvider _publicKey;
        public static string Encrypt(string text, string key)
        {
            _publicKey = GetPublicKeyFromPemFile(key);
            var encryptedBytes = _publicKey.Encrypt(Encoding.UTF8.GetBytes(text), false);
            return Convert.ToBase64String(encryptedBytes);
        }
        public static string Decrypt(string encrypted, string key)
        {
            _privateKey = GetPrivateKeyFromPemFile(key);
            var decryptedBytes = _privateKey.Decrypt(Convert.FromBase64String(encrypted), false);
            return Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length);
        }
        private static RSACryptoServiceProvider GetPrivateKeyFromPemFile(string key)
        {
            using (TextReader privateKeyTextReader = new StringReader(key))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }
        private static RSACryptoServiceProvider GetPublicKeyFromPemFile(String key)
        {
            using (TextReader publicKeyTextReader = new StringReader(key))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParam);
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }
    }
}

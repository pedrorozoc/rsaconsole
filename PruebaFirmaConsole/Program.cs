using System;
using System.IO;
using System.Security.Cryptography;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PruebaFirmaConsole
{
    class Program
    {
        
        static void Main(string[] args)
        {

            string dato = "Este texto se va a firmar";
        
            
            Console.Write("Enter your password: ");

            string password = GetPassword();

            Console.WriteLine("");
            string filename = "";

            if (args.Length == 0)
            {
                filename = "temp";
            }
            else
            {
                filename = args[0];
            }

            X509Certificate2 cert= LoadCertificate(filename, password);
      

            Console.WriteLine("HasPrivateKey: "+cert.HasPrivateKey);
            
            RSACng privatekey = (RSACng)cert.GetRSAPrivateKey();

            string firma = SignData(dato, privatekey);            
            Console.WriteLine("firma: " + firma);     
            

            System.Security.Cryptography.RSACng publickey = (RSACng)cert.GetRSAPrivateKey();

            bool verificado = VerifyData(dato, firma, publickey.ExportParameters(false));

            Console.WriteLine("Fin!!! : "+verificado);


        }

        //para verificar la firma de un texto
        public static bool VerifyData(string originalMessage, string signedMessage, RSAParameters publicKey)
        {
            bool success = false;
            using (var rsa = new RSACryptoServiceProvider())
            {
                //Don't do this, do the same as you did in SignData:
                //byte[] bytesToVerify = Convert.FromBase64String(originalMessage);
                var encoder = new UTF8Encoding();
                byte[] bytesToVerify = encoder.GetBytes(originalMessage);

                byte[] signedBytes = Convert.FromBase64String(signedMessage);
                try
                {
                    rsa.ImportParameters(publicKey);

                    SHA512Managed Hash = new SHA512Managed();

                    byte[] hashedData = Hash.ComputeHash(signedBytes);

                    success = rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA256"), signedBytes);
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return success;
        }
        //para firmar un texto
        public static string SignData (string message, RSACng privatekey)
        {
            byte[] signedBytes;            
            var encoder = new UTF8Encoding();
            byte[] originalData = encoder.GetBytes(message);

            signedBytes =privatekey.SignData(originalData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signedBytes);
        }

        //cargar el certificado
        public static X509Certificate2 LoadCertificate (string fileName, string password)
        {            
            //verificar que el archivo exista
            if (File.Exists(fileName + ".pfx"))
            {
                Console.WriteLine("Se va a cargar el archivo...");
                //se carga y retorna
                X509Certificate2 cert = new X509Certificate2(fileName + ".pfx",password);
                return cert;
            }
            else
            {
                //si el archivo no existe, se crea uno, se carga y se retorna
                X509Certificate2 cer = CreateCertificate(fileName, password);               
                return cer;
            }
            
            
        }

        //Se crea un certificado autofirmado nuevo, 
        //se almacena en un archivo pfx con la clave privada y un cer con la pública
        private static X509Certificate2 CreateCertificate(string nombreArchivo, string password)
        {
            var ecdsa = RSACng.Create(); // generate asymmetric key pair
            CertificateRequest req = new CertificateRequest("cn=dian", ecdsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);           
            
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            cert.FriendlyName = "usuario";
            


            // Create PFX (PKCS #12) with private key
            File.WriteAllBytes(nombreArchivo+".pfx", cert.Export(X509ContentType.Pfx, password));

            // Create Base 64 encoded CER (public key only)
            File.WriteAllText(nombreArchivo+".cer",
                "-----BEGIN CERTIFICATE-----\r\n"
                + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
                + "\r\n-----END CERTIFICATE-----");


            return cert;
        }

        //para eller la contraseña
        public static string GetPassword()
        {
            string pass = "";
            do
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                // Backspace Should Not Work
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pass += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                    {
                        pass = pass.Substring(0, (pass.Length - 1));
                        Console.Write("\b \b");
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        break;
                    }
                }
            } while (true);
            return pass;
        }
    }
     
}

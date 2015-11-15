using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Mono.Options;
using Org.BouncyCastle.Security;

namespace PdfSigner
{
    public class Program
    {
        public int Main(string[] args)
        {
            bool help = (args.Length == 0);
            Stream input = null;
            Stream output = null;
            string thumbprint = null;
            string p12 = null;
            SecureString password = null;

            var options = new OptionSet
            {
                { "h|help", "Show this help.", p => help = p != null },
                { "f|file:", "Input file path -or- file is read from stdin.", p => input = File.OpenRead(p) },
                { "o|out:", "Output file path -or- file is written to stdout.", p => output = File.OpenWrite(p) },
                { "tp:", "Signing certificate thumbprint to look up in My store of current user.", p => thumbprint = p },
                { "p12:", "Signing certificate (PKCS12) path.", p => p12 = p },
                { "pwd:", "Password for PKCS12 certificate file.", p => {
                    password = new SecureString();
                    foreach (var c in p) password.AppendChar(c);
                    password.MakeReadOnly();
                }},
            };

            options.Parse(args);

            if (help)
            {
                options.WriteOptionDescriptions(Console.Out);
                return 0;
            }

            if (input == null) input = Console.OpenStandardInput();
            if (output == null) output = Console.OpenStandardOutput();

            X509Certificate2 certificate = null;

            if (p12 != null)
            {
                certificate = new X509Certificate2(p12, password, X509KeyStorageFlags.Exportable);
            }
            else
            {
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

                try
                {
                    store.Open(OpenFlags.ReadOnly);

                    certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true)
                        .OfType<X509Certificate2>()
                        .FirstOrDefault();
                }
                finally
                {
                    store.Close();
                }
            }

            password?.Dispose();

            if (certificate == null)
            {
                Console.Error.WriteLine("No certificate found.");
                return 101;
            }

            if ((certificate.PrivateKey as ICspAsymmetricAlgorithm)?.CspKeyContainerInfo?.Exportable == false)
            {
                Console.Error.WriteLine("Private key is not exportable.");
                return 102;
            }

            using (output)
            using (input)
            {
                SignPdf(input, output, certificate);
            }

            return 0;
        }

        private void SignPdf(Stream input, Stream output, X509Certificate2 cert)
        {
            var bcCert = DotNetUtilities.FromX509Certificate(cert);
            var bcKey = DotNetUtilities.GetKeyPair(cert.PrivateKey);

            var signature = new PrivateKeySignature(bcKey.Private, "SHA-512");

            var tsaClient = new TSAClientBouncyCastle("http://timestamp.globalsign.com/scripts/timestamp.dll");

            using (var reader = new PdfReader(input))
            using (var stamper = PdfStamper.CreateSignature(reader, output, '\0'))
            {
                MakeSignature.SignDetached(stamper.SignatureAppearance, signature, new[] { bcCert }, null, null, tsaClient, 0, CryptoStandard.CMS);
            }
        }
    }
}
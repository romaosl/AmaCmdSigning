using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using System.IO;
using iText.IO.Image;
using iText.Signatures;
using LA.CmdSigning;
using System.Text;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SigningClientApp
{
    static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static int Main(string[] args)
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if ((args.Length==7 || args.Length == 8) && args[0] == "-get_hash")
            {
                string pdfToBeSigned = args[1];//Ficheiro PDF a assinar
                byte[] cert_bytes = File.ReadAllBytes(args[2]);//Ficheiro do certificado
                string temporaryPdf = args[3];//Fichero PDF temporário a criar
                string hashFile = args[4];//Ficheiro do hash a criar
                string nakedHashFile = args[5];//Ficheiro do naked hash a criar
                string signatureIdFile = args[6];
                string signatureInfoFile = args.Length == 8 ? args[7] : "";

                string signatureId = File.Exists(signatureIdFile) ? File.ReadAllText(signatureIdFile) : "";
                string signatureText = "";
                ImageData signatureLogo = null;
                bool createSignatureIdFile = (signatureId == "");
                float x = 10;
                float y = 750;
                float width = 150;
                float height = 50;
                int pageNumber = 1;

                if (signatureInfoFile != "")
                {
                    using (StreamReader reader = File.OpenText(signatureInfoFile))
                    {
                        string pathLogo = reader.ReadLine();
                        x = float.Parse(reader.ReadLine());
                        y = float.Parse(reader.ReadLine());
                        width = float.Parse(reader.ReadLine());
                        height = float.Parse(reader.ReadLine());
                        pageNumber = int.Parse(reader.ReadLine());

                        if (pathLogo != "")
                            signatureLogo = ImageDataFactory.Create(new Uri(pathLogo));
                        signatureText = reader.ReadToEnd();
                    }
                }

                var userCertificatesChain = new X509CertificateParser().ReadCertificates(cert_bytes).Cast<X509Certificate>().ToList();
                // freetsa -> config information: https://www.freetsa.org/guide/demonstration-digitally-signed-PDF-documents.html
                var tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr");
                // crl list for revocation
                var crlClients = new List<ICrlClient> { new CrlClientOnline(userCertificatesChain.ToArray()) };
                // added ocsp client
                var ocspClient = new OcspClientBouncyCastle(null);

                PdfSigningManager pdfSigner = new PdfSigningManager(userCertificatesChain, crlClients: crlClients, ocspClient: ocspClient, tsaClient: tsaClient, signatureFieldname: signatureId);
                //var pathToLogo = "pena.jpg";
                //var logo = ImageDataFactory.CreateJpeg(new Uri(pathToLogo));
                HashesForSigning hashInformation = pdfSigner.CreateTemporaryPdfForSigning(new SigningInformation(pdfToBeSigned,
                                                                                                       temporaryPdf,
                                                                                                       Reason: "",
                                                                                                       Location: "",
                                                                                                       Logo: signatureLogo,
                                                                                                       FullText: signatureText,
                                                                                                       x: x,
                                                                                                       y: y,
                                                                                                       width: width,
                                                                                                       height: height,
                                                                                                       PageNumber: pageNumber)) ;
                if (createSignatureIdFile)
                    File.WriteAllText(signatureIdFile, pdfSigner.SignatureFieldName);

                File.WriteAllBytes(hashFile, hashInformation.HashForSigning);
                File.WriteAllBytes(nakedHashFile, hashInformation.NakedHash);
                return 0;
            }
            else if (args.Length == 7 && args[0] == "-sign_pdf")
            {
                string temporaryPdf = args[1];//Fichero temporário já criado
                byte[] cert_bytes = File.ReadAllBytes(args[2]);//Ficheiro do certificado
                string finalPdf = args[3];//Ficheiro final a criar com a assinatura
                byte[] signature_Bytes = File.ReadAllBytes(args[4]);//Ficheiro com a assinatura
                byte[] nakedHash = File.ReadAllBytes(args[5]);//Ficheiro com o naked hash
                string signatureIdFile = args[6];

                string signatureId = File.ReadAllText(signatureIdFile);

                var userCertificatesChain = new X509CertificateParser().ReadCertificates(cert_bytes).Cast<X509Certificate>().ToList();
                // freetsa -> config information: https://www.freetsa.org/guide/demonstration-digitally-signed-PDF-documents.html
                var tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr");
                // crl list for revocation
                var crlClients = new List<ICrlClient> { new CrlClientOnline(userCertificatesChain.ToArray()) };
                // added ocsp client
                var ocspClient = new OcspClientBouncyCastle(null);

                PdfSigningManager pdfSigner = new PdfSigningManager(userCertificatesChain, crlClients: crlClients, ocspClient: ocspClient, tsaClient: tsaClient, signatureFieldname: signatureId);

                pdfSigner.SignIntermediatePdf(new SignatureInformation(temporaryPdf,
                                                       finalPdf,
                                                       signature_Bytes,
                                                       nakedHash,//hashInformation.NakedHash,
                                                       null));
                return 0;
            }
            else
            {
                System.Windows.Forms.MessageBox.Show(
                    "Tem que correr de uma das duas formas:\n\n" +
                    "   CmdWinDEVSigningClient -get_hash [Ficheiro PDF a assinar] [Ficheiro do certificado] [Fichero PDF temporário a criar] [Ficheiro do hash a criar] [Ficheiro do naked hash a criar] [Ficheiro com o ident. do componente de assinatura] [Opcional: Ficheiro com o caminho do logotipo e o texto da assinatura]\n\n" +
                    "   CmdWinDEVSigningClient -sign_pdf [Fichero temporário já criado] [Ficheiro do certificado] [Ficheiro final a criar com a assinatura] [Ficheiro com a assinatura] [Ficheiro com o naked hash] [Ficheiro com o ident. do componente de assinatura]"
                    );
                return -1;
            }

        }
    }
}

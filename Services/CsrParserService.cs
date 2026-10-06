using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using PkiPortal.Models;

namespace PkiPortal.Services;

public interface ICsrParserService
{
    CsrParseResponse ParseCsr(string csrPem);
}

public class CsrParserService : ICsrParserService
{
    private static readonly Regex PemHeaderRegex = new(@"-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----[\s\S]+?-----END (?:NEW )?CERTIFICATE REQUEST-----", RegexOptions.Compiled);

    public CsrParseResponse ParseCsr(string csrPem)
    {
        var response = new CsrParseResponse();

        if (string.IsNullOrWhiteSpace(csrPem))
        {
            response.Success = false;
            response.ErrorMessage = "Il contenuto del CSR è vuoto.";
            return response;
        }

        try
        {
            // Normalizzazione PEM se l'utente ha incollato solo Base64
            string cleanPem = csrPem.Trim();
            if (!cleanPem.Contains("-----BEGIN"))
            {
                cleanPem = $"-----BEGIN CERTIFICATE REQUEST-----\r\n{cleanPem}\r\n-----END CERTIFICATE REQUEST-----";
            }

            var match = PemHeaderRegex.Match(cleanPem);
            if (!match.Success)
            {
                response.Success = false;
                response.ErrorMessage = "Formato PEM non valido. Assicurarsi che inizi con '-----BEGIN CERTIFICATE REQUEST-----'.";
                return response;
            }

            // In .NET 8 carichiamo il CSR con CertificateRequest
            var certReq = CertificateRequest.LoadSigningRequestPem(
                cleanPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            response.Subject = certReq.SubjectName.Name;
            response.CommonName = ExtractCommonName(certReq.SubjectName);

            // Algoritmo chiave e dimensione
            if (certReq.PublicKey != null)
            {
                var rsa = certReq.PublicKey.GetRSAPublicKey();
                if (rsa != null)
                {
                    response.KeyAlgorithm = "RSA";
                    response.KeySize = rsa.KeySize;
                }
                else
                {
                    var ecdsa = certReq.PublicKey.GetECDsaPublicKey();
                    if (ecdsa != null)
                    {
                        response.KeyAlgorithm = "ECDSA";
                        response.KeySize = ecdsa.KeySize;
                    }
                    else
                    {
                        response.KeyAlgorithm = certReq.PublicKey.Oid.FriendlyName ?? certReq.PublicKey.Oid.Value;
                        response.KeySize = 0;
                    }
                }
            }

            // Estrazione Subject Alternative Names (SAN)
            foreach (var ext in certReq.CertificateExtensions)
            {
                if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name OID
                {
                    var sanExt = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                    foreach (var dns in sanExt.EnumerateDnsNames())
                    {
                        response.SubjectAlternativeNames.Add($"DNS:{dns}");
                    }
                    foreach (var ip in sanExt.EnumerateIPAddresses())
                    {
                        response.SubjectAlternativeNames.Add($"IP:{ip}");
                    }
                }
            }

            response.Success = true;
            return response;
        }
        catch (Exception)
        {
            response.Success = false;
            // SECURITY: non esporre ex.Message (potrebbe contenere dettagli interni).
            response.ErrorMessage = "Errore durante il parsing del CSR: la richiesta non è nel formato PKCS#10 atteso. Verificare il contenuto del CSR.";
            return response;
        }
    }

    private static string? ExtractCommonName(X500DistinguishedName dn)
    {
        foreach (var part in dn.Name.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed.Substring(3);
            }
        }
        return null;
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PkiPortal.Models;

namespace PkiPortal.Services;

public class AcmeCryptoService : IAcmeCryptoService
{
    private readonly ILogger<AcmeCryptoService> _logger;

    public AcmeCryptoService(ILogger<AcmeCryptoService> logger)
    {
        _logger = logger;
    }

    public string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public string Base64UrlEncode(string text)
    {
        return Base64UrlEncode(Encoding.UTF8.GetBytes(text));
    }

    public byte[] Base64UrlDecode(string input)
    {
        string padded = input.Trim().Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    public string Base64UrlDecodeToString(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return Encoding.UTF8.GetString(Base64UrlDecode(input));
    }

    /// <summary>
    /// Calcola il JWK Thumbprint secondo RFC 7638.
    /// Ordina tassativamente le proprietà in ordine alfabetico senza spazi bianchi.
    /// </summary>
    public string ComputeJwkThumbprint(AcmeJwk jwk)
    {
        string canonicalJson;
        if (string.Equals(jwk.Kty, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(jwk.E) || string.IsNullOrEmpty(jwk.N))
                throw new ArgumentException("I campi 'e' e 'n' sono obbligatori per le chiavi RSA.");

            canonicalJson = $"{{\"e\":\"{jwk.E}\",\"kty\":\"RSA\",\"n\":\"{jwk.N}\"}}";
        }
        else if (string.Equals(jwk.Kty, "EC", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(jwk.Crv) || string.IsNullOrEmpty(jwk.X) || string.IsNullOrEmpty(jwk.Y))
                throw new ArgumentException("I campi 'crv', 'x' e 'y' sono obbligatori per le chiavi EC.");

            canonicalJson = $"{{\"crv\":\"{jwk.Crv}\",\"kty\":\"EC\",\"x\":\"{jwk.X}\",\"y\":\"{jwk.Y}\"}}";
        }
        else
        {
            throw new NotSupportedException($"Tipo di chiave '{jwk.Kty}' non supportato per il calcolo del JWK Thumbprint.");
        }

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson));
        return Base64UrlEncode(hash);
    }

    public AcmeJwsHeader? ParseProtectedHeader(string protectedHeaderB64)
    {
        try
        {
            string json = Base64UrlDecodeToString(protectedHeaderB64);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var header = new AcmeJwsHeader();
            if (root.TryGetProperty("alg", out var algElem)) header.Alg = algElem.GetString() ?? "";
            if (root.TryGetProperty("kid", out var kidElem)) header.Kid = kidElem.GetString();
            if (root.TryGetProperty("url", out var urlElem)) header.Url = urlElem.GetString() ?? "";

            if (root.TryGetProperty("nonce", out var nonceElem))
            {
                if (nonceElem.ValueKind == JsonValueKind.Array && nonceElem.GetArrayLength() > 0)
                    header.Nonce = nonceElem[0].GetString() ?? "";
                else if (nonceElem.ValueKind == JsonValueKind.String)
                    header.Nonce = nonceElem.GetString() ?? "";
            }

            if (root.TryGetProperty("jwk", out var jwkElem) && jwkElem.ValueKind == JsonValueKind.Object)
            {
                header.Jwk = JsonSerializer.Deserialize<AcmeJwk>(jwkElem.GetRawText(), new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            }

            return header;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Errore durante il parsing del protected header JWS.");
            return null;
        }
    }

    public bool VerifyJwsSignature(string protectedHeaderB64, string payloadB64, string signatureB64, AcmeJwk jwk, out string? errorMessage)
    {
        errorMessage = null;
        try
        {
            var header = ParseProtectedHeader(protectedHeaderB64);
            if (header == null)
            {
                errorMessage = "Impossibile decodificare l'header protetto JWS.";
                return false;
            }

            byte[] dataToVerify = Encoding.ASCII.GetBytes($"{protectedHeaderB64}.{payloadB64}");
            byte[] signature = Base64UrlDecode(signatureB64);

            string alg = header.Alg?.ToUpperInvariant() ?? string.Empty;

            if (string.Equals(jwk.Kty, "RSA", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(jwk.N) || string.IsNullOrEmpty(jwk.E))
                {
                    errorMessage = "Parametri RSA mancanti (n o e).";
                    return false;
                }

                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Base64UrlDecode(jwk.N),
                    Exponent = Base64UrlDecode(jwk.E)
                });

                HashAlgorithmName hashAlg = alg switch
                {
                    "RS256" or "PS256" => HashAlgorithmName.SHA256,
                    "RS384" or "PS384" => HashAlgorithmName.SHA384,
                    "RS512" or "PS512" => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256
                };

                RSASignaturePadding padding = alg.StartsWith("PS", StringComparison.OrdinalIgnoreCase)
                    ? RSASignaturePadding.Pss
                    : RSASignaturePadding.Pkcs1;

                bool isValid = rsa.VerifyData(dataToVerify, signature, hashAlg, padding);
                if (!isValid)
                {
                    errorMessage = "Firma RSA non valida.";
                    return false;
                }
                return true;
            }
            else if (string.Equals(jwk.Kty, "EC", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(jwk.X) || string.IsNullOrEmpty(jwk.Y) || string.IsNullOrEmpty(jwk.Crv))
                {
                    errorMessage = "Parametri EC mancanti (x, y o crv).";
                    return false;
                }

                ECCurve curve = jwk.Crv.ToUpperInvariant() switch
                {
                    "P-256" => ECCurve.NamedCurves.nistP256,
                    "P-384" => ECCurve.NamedCurves.nistP384,
                    "P-521" => ECCurve.NamedCurves.nistP521,
                    _ => throw new NotSupportedException($"Curva EC '{jwk.Crv}' non supportata.")
                };

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportParameters(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint
                    {
                        X = Base64UrlDecode(jwk.X),
                        Y = Base64UrlDecode(jwk.Y)
                    }
                });

                HashAlgorithmName hashAlg = jwk.Crv.ToUpperInvariant() switch
                {
                    "P-256" => HashAlgorithmName.SHA256,
                    "P-384" => HashAlgorithmName.SHA384,
                    "P-521" => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256
                };

                // Verifica IEEE P1363 (standard JWS RFC 7515) o fallback DER
                bool isValid = ecdsa.VerifyData(dataToVerify, signature, hashAlg, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                            || ecdsa.VerifyData(dataToVerify, signature, hashAlg, DSASignatureFormat.Rfc3279DerSequence);

                if (!isValid)
                {
                    errorMessage = "Firma ECDSA non valida.";
                    return false;
                }
                return true;
            }
            else
            {
                errorMessage = $"Tipo di chiave JWK '{jwk.Kty}' non supportato.";
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Eccezione durante la verifica della firma JWS.");
            errorMessage = $"Errore di verifica firma: {ex.Message}";
            return false;
        }
    }

    public string ConvertDerCsrToPem(byte[] derCsr)
    {
        string base64 = Convert.ToBase64String(derCsr);
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        for (int i = 0; i < base64.Length; i += 64)
        {
            sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }
        sb.AppendLine("-----END CERTIFICATE REQUEST-----");
        return sb.ToString();
    }
}

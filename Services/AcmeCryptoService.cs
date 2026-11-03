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

    /// <summary>
    /// SECURITY (2.3.1): valida la forza minima della chiave pubblica di un
    /// account ACME prima della registrazione (RFC 8555 Sez. 6.2):
    /// RSA &lt; 2048 bit e chiavi degenerate rifiutate; per EC solo curve
    /// NIST P-256/384/521 con coordinate coerenti.
    /// </summary>
    public bool ValidateJwkStrength(AcmeJwk jwk, out string? errorMessage)
    {
        errorMessage = null;
        try
        {
            if (string.Equals(jwk.Kty, "RSA", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(jwk.N) || string.IsNullOrEmpty(jwk.E))
                {
                    errorMessage = "Parametri RSA mancanti (n o e).";
                    return false;
                }

                byte[] modulus = Base64UrlDecode(jwk.N);
                byte[] exponent = Base64UrlDecode(jwk.E);

                // Dimensione minima del modulo: 2048 bit (256 byte).
                if (modulus.Length < 256)
                {
                    errorMessage = $"Chiave RSA troppo debole: il modulo deve avere almeno 2048 bit (ricevuti {modulus.Length * 8}).";
                    return false;
                }

                // Esponente: piccolo intero dispari >= 3 (standard: 65537).
                if (exponent.Length == 0 || exponent.Length > 8)
                {
                    errorMessage = "Esponente RSA non valido.";
                    return false;
                }
                ulong e = 0;
                for (int i = exponent.Length - 1; i >= 0; i--) e = (e << 8) | exponent[i];
                if (e < 3 || e % 2 == 0)
                {
                    errorMessage = "Esponente RSA non valido (deve essere dispari e >= 3).";
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

                string crv = (jwk.Crv ?? string.Empty).ToUpperInvariant();
                int expected = crv switch
                {
                    "P-256" => 32,
                    "P-384" => 48,
                    "P-521" => 66,
                    _ => -1
                };
                if (expected < 0)
                {
                    errorMessage = $"Curva EC '{jwk.Crv}' non supportata (consentite: P-256, P-384, P-521).";
                    return false;
                }

                byte[] x = Base64UrlDecode(jwk.X);
                byte[] y = Base64UrlDecode(jwk.Y);
                if (x.Length != expected || y.Length != expected)
                {
                    errorMessage = "Coordinate EC non coerenti con la curva dichiarata.";
                    return false;
                }

                return true;
            }
            else
            {
                errorMessage = $"Tipo di chiave JWK '{jwk.Kty}' non supportato (consentite: RSA, EC).";
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "JWK non interpretabile durante la validazione della forza chiave.");
            errorMessage = "JWK non interpretabile.";
            return false;
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

            // SECURITY (2.3.1): allowlist esplicita degli algoritmi (RFC 8555
            // Sez. 6.2). Alg sconosciuti o "none" vengono rifiutati
            // esplicitamente invece di cadere in un fallback.
            string alg = (header.Alg ?? string.Empty).ToUpperInvariant();

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

                HashAlgorithmName hashAlg;
                RSASignaturePadding padding;
                switch (alg)
                {
                    case "RS256": hashAlg = HashAlgorithmName.SHA256; padding = RSASignaturePadding.Pkcs1; break;
                    case "RS384": hashAlg = HashAlgorithmName.SHA384; padding = RSASignaturePadding.Pkcs1; break;
                    case "RS512": hashAlg = HashAlgorithmName.SHA512; padding = RSASignaturePadding.Pkcs1; break;
                    case "PS256": hashAlg = HashAlgorithmName.SHA256; padding = RSASignaturePadding.Pss; break;
                    case "PS384": hashAlg = HashAlgorithmName.SHA384; padding = RSASignaturePadding.Pss; break;
                    case "PS512": hashAlg = HashAlgorithmName.SHA512; padding = RSASignaturePadding.Pss; break;
                    default:
                        errorMessage = $"Algoritmo JWS '{header.Alg}' non supportato (consentiti: RS256, RS384, RS512, PS256, PS384, PS512).";
                        return false;
                }

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

                // SECURITY (2.3.1): l'alg deve corrispondere alla curva (RFC 7518);
                // combinazioni non previste vengono rifiutate esplicitamente.
                string crv = (jwk.Crv ?? string.Empty).ToUpperInvariant();
                ECCurve curve;
                HashAlgorithmName hashAlg;
                switch (alg)
                {
                    case "ES256" when string.Equals(crv, "P-256", StringComparison.OrdinalIgnoreCase):
                        curve = ECCurve.NamedCurves.nistP256; hashAlg = HashAlgorithmName.SHA256; break;
                    case "ES384" when string.Equals(crv, "P-384", StringComparison.OrdinalIgnoreCase):
                        curve = ECCurve.NamedCurves.nistP384; hashAlg = HashAlgorithmName.SHA384; break;
                    case "ES512" when string.Equals(crv, "P-521", StringComparison.OrdinalIgnoreCase):
                        curve = ECCurve.NamedCurves.nistP521; hashAlg = HashAlgorithmName.SHA512; break;
                    default:
                        errorMessage = $"Combinazione alg/curva non supportata: alg '{header.Alg}' con curva '{jwk.Crv}' (consentite: ES256/P-256, ES384/P-384, ES512/P-521).";
                        return false;
                }

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
            // SECURITY: non esporre ex.Message al client (dettagli interni).
            errorMessage = "Errore di verifica firma.";
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

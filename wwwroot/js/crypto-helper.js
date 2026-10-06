/**
 * Modulo Crittografico Client-Side (HTML5 Web Crypto & Forge)
 * Consente la generazione di chiavi private, CSR PKCS#10 e packaging PKCS#12 (PFX)
 * direttamente nel browser dell'utente. La chiave privata NON lascia mai il dispositivo.
 */

window.CryptoHelper = (function () {
    'use strict';

    /**
     * Genera una coppia di chiavi e un CSR PKCS#10 conforme alle specifiche RFC 2986
     */
    async function generateCsr(params) {
        const {
            commonName,
            organization = '',
            organizationalUnit = '',
            country = '',
            state = '',
            locality = '',
            sans = [],
            keyType = 'RSA-2048'
        } = params;

        return new Promise((resolve, reject) => {
            try {
                let keyBits = 2048;
                if (keyType === 'RSA-4096') keyBits = 4096;
                else if (keyType === 'RSA-3072') keyBits = 3072;

                // Generazione asincrona coppia di chiavi RSA nel client
                forge.pki.rsa.generateKeyPair({ bits: keyBits, workers: -1 }, function (err, keypair) {
                    if (err) {
                        return reject(new Error('Errore durante la generazione della coppia di chiavi: ' + err.message));
                    }

                    try {
                        const csr = forge.pki.createCertificationRequest();
                        csr.publicKey = keypair.publicKey;

                        // Costruzione del Subject Distinguished Name (DN)
                        const attrs = [];
                        if (commonName) attrs.push({ name: 'commonName', value: commonName });
                        if (organization) attrs.push({ name: 'organizationName', value: organization });
                        if (organizationalUnit) attrs.push({ name: 'organizationalUnitName', value: organizationalUnit });
                        if (country) attrs.push({ name: 'countryName', value: country });
                        if (state) attrs.push({ name: 'stateOrProvinceName', value: state });
                        if (locality) attrs.push({ name: 'localityName', value: locality });

                        csr.setSubject(attrs);

                        // Aggiunta estensione Subject Alternative Name (SAN) se presente
                        if (sans && sans.length > 0) {
                            const altNames = sans.map(s => {
                                const typeUpper = (s.type || 'DNS').toUpperCase();
                                if (typeUpper === 'IP') {
                                    return { type: 7, ip: s.value.trim() }; // IPAddress = tag 7
                                } else if (typeUpper === 'EMAIL') {
                                    return { type: 1, value: s.value.trim() }; // rfc822Name = tag 1
                                } else if (typeUpper === 'URI') {
                                    return { type: 6, value: s.value.trim() }; // uniformResourceIdentifier = tag 6
                                } else {
                                    return { type: 2, value: s.value.trim() }; // dNSName = tag 2
                                }
                            });

                            csr.setAttributes([{
                                name: 'extensionRequest',
                                extensions: [{
                                    name: 'subjectAltName',
                                    altNames: altNames
                                }]
                            }]);
                        }

                        // Firma del CSR con la chiave privata creata nel browser
                        csr.sign(keypair.privateKey, forge.md.sha256.create());

                        // Conversione in PEM
                        const csrPem = forge.pki.certificationRequestToPem(csr);

                        resolve({
                            csrPem: csrPem,
                            privateKey: keypair.privateKey,
                            publicKey: keypair.publicKey,
                            keyType: keyType,
                            keySize: keyBits
                        });
                    } catch (csrErr) {
                        reject(new Error('Errore creazione PKCS#10: ' + csrErr.message));
                    }
                });
            } catch (ex) {
                reject(ex);
            }
        });
    }

    /**
     * Parsing ultra-robusto di certificato X.509 da blocco PEM o Base64
     */
    function pemToCertificate(pem) {
        if (!pem || typeof pem !== 'string') return null;
        try {
            const lines = pem.split(/\r?\n/);
            let base64 = '';
            let inBlock = false;
            let foundBlock = false;

            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed.startsWith('-----BEGIN CERTIFICATE') || trimmed.startsWith('-----BEGIN X509') || trimmed.startsWith('-----BEGIN TRUSTED')) {
                    inBlock = true;
                    foundBlock = true;
                    base64 = '';
                    continue;
                }
                if (trimmed.startsWith('-----END')) {
                    inBlock = false;
                    if (base64.length > 0) break;
                    continue;
                }
                if (inBlock && trimmed.length > 0 && !trimmed.includes(':')) {
                    base64 += trimmed;
                }
            }

            if (!foundBlock || !base64) {
                base64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
            }

            if (!base64) return null;

            const derBytes = forge.util.decode64(base64);
            const asn1 = forge.asn1.fromDer(derBytes, { strict: false });
            return forge.pki.certificateFromAsn1(asn1);
        } catch (ex) {
            console.warn('Fallback parsing certificato:', ex);
            try {
                return forge.pki.certificateFromPem(pem);
            } catch (fallbackEx) {
                throw ex;
            }
        }
    }

    /**
     * Estrae tutti i certificati presenti in una catena PEM (Root / Intermedi)
     */
    function pemChainToCertificates(chainPem) {
        if (!chainPem || typeof chainPem !== 'string') return [];
        const certList = [];
        // NB: la parte di tipo è OPZIONALE (*): i blocchi standard
        // "-----BEGIN CERTIFICATE-----" non hanno prefisso tra BEGIN e CERTIFICATE.
        const matches = chainPem.match(/-----BEGIN [A-Z0-9- ]*CERTIFICATE-----[\s\S]+?-----END [A-Z0-9- ]*CERTIFICATE-----/g);
        if (matches) {
            for (const block of matches) {
                try {
                    const c = pemToCertificate(block);
                    if (c && c.serialNumber) {
                        certList.push(c);
                    }
                } catch (e) {
                    console.warn('Impossibile caricare certificato della catena:', e);
                }
            }
        }
        return certList;
    }

    /**
     * Costruisce un file PKCS#12 (.PFX) protetto da password combinando
     * la chiave privata generata nel browser e il certificato firmato emesso da ADCS.
     */
    function createPfxBundle(privateKey, certPem, chainPem, password) {
        try {
            if (!certPem || typeof certPem !== 'string') {
                throw new Error('Certificato emesso mancante o non valido.');
            }

            let keyObj = privateKey;
            if (typeof keyObj === 'string') {
                keyObj = forge.pki.privateKeyFromPem(keyObj);
            }

            // Parsing robusto del certificato emesso
            const leafCert = pemToCertificate(certPem);
            if (!leafCert) {
                throw new Error('Impossibile decodificare il certificato X.509 emesso.');
            }

            const certs = [leafCert];

            // Aggiunta certificati della catena di emissione completa (Intermedi + Root CA)
            const cleanSerial = s => (s || '').replace(/^0+/, '').toLowerCase();
            const leafSerialClean = cleanSerial(leafCert.serialNumber);

            if (chainPem) {
                const chainCerts = pemChainToCertificates(chainPem);
                let chainAddedCount = 0;
                for (const chainCert of chainCerts) {
                    const chainSerialClean = cleanSerial(chainCert.serialNumber);
                    if (chainSerialClean !== leafSerialClean) {
                        const exists = certs.some(c => cleanSerial(c.serialNumber) === chainSerialClean);
                        if (!exists) {
                            certs.push(chainCert);
                            chainAddedCount++;
                            let subjectCn = 'CA';
                            try {
                                const cn = chainCert.subject.getField('CN');
                                if (cn && cn.value) subjectCn = cn.value;
                            } catch (e) { }
                            console.log(`[PFX Bundle] + Catena [${chainAddedCount}]: CN=${subjectCn}, Serial=${chainCert.serialNumber}`);
                        }
                    }
                }
                console.log(`[PFX Bundle] Inclusi ${chainAddedCount} certificati della catena di emissione (totale certificati nel bundle: ${certs.length}).`);
            } else {
                console.warn('[PFX Bundle] Nessuna catena di certificati fornita: il PFX conterrà solo il certificato foglia e la chiave privata.');
            }

            // Friendly name sicuro
            let friendlyName = 'PKI-Certificate';
            try {
                const cnField = leafCert.subject.getField('CN');
                if (cnField && cnField.value) {
                    friendlyName = cnField.value;
                }
            } catch (e) { }

            // Creazione contenitore PKCS#12
            const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keyObj, certs, password || '', {
                generateLocalKeyId: true,
                friendlyName: friendlyName,
                algorithm: '3des' // Massima compatibilità con Windows / IIS / Android / macOS
            });

            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const p12Bytes = new Uint8Array(p12Der.length);
            for (let i = 0; i < p12Der.length; i++) {
                p12Bytes[i] = p12Der.charCodeAt(i);
            }

            return new Blob([p12Bytes], { type: 'application/x-pkcs12' });
        } catch (ex) {
            console.error('Dettagli errore PFX:', ex);
            throw new Error('Errore creazione file PFX: ' + ex.message);
        }
    }

    /**
     * Esporta la chiave privata in formato PEM (PKCS#8 o PKCS#1)
     */
    function exportPrivateKeyPem(privateKey) {
        return forge.pki.privateKeyToPem(privateKey);
    }

    return {
        generateCsr: generateCsr,
        createPfxBundle: createPfxBundle,
        exportPrivateKeyPem: exportPrivateKeyPem
    };
})();

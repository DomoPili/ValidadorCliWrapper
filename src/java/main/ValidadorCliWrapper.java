import ec.gob.firmadigital.libreria.crl.ServicioCRL;
import ec.gob.firmadigital.libreria.ocsp.ValidadorOCSP;
import ec.gob.firmadigital.libreria.sign.SignInfo;
import ec.gob.firmadigital.libreria.sign.pdf.PadesSigner;
import ec.gob.firmadigital.libreria.sign.xades.XAdESSigner;
import ec.gob.firmadigital.libreria.utils.BouncyCastleUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

public class ValidadorCliWrapper {

    private static final Map<String, CrlCacheEntry> CRL_CACHE = new HashMap<>();

    private static class CrlCacheEntry {
        final X509CRL crl;
        final String error;

        CrlCacheEntry(X509CRL crl, String error) {
            this.crl = crl;
            this.error = error;
        }
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Uso: ValidadorCliWrapper <ruta_archivo> [url_ocsp] [url_crl]");
            System.exit(2);
        }

        Path ruta = Paths.get(args[0]);
        String urlOcspArg = args.length >= 2 && !args[1].isBlank() ? args[1].trim() : null;
        String urlCrlArg = args.length >= 3 && !args[2].isBlank() ? args[2].trim() : null;

        if (!Files.exists(ruta)) {
            System.err.println("Archivo no encontrado: " + ruta);
            System.exit(3);
        }

        try {
            BouncyCastleUtils.initializeBouncyCastle();

            byte[] contenido = Files.readAllBytes(ruta);
            String nombreLower = ruta.getFileName().toString().toLowerCase(Locale.ROOT);
            List<SignInfo> firmas;
            String tipoDocumento;

            if (nombreLower.endsWith(".pdf")) {
                tipoDocumento = "PDF";
                PadesSigner signer = new PadesSigner();
                firmas = signer.getSigners(contenido);
            } else if (nombreLower.endsWith(".xml")) {
                tipoDocumento = "XML";
                XAdESSigner signer = new XAdESSigner();
                firmas = signer.getSignInfo(contenido);
            } else {
                System.err.println("Formato no soportado (use .pdf o .xml): " + ruta);
                System.exit(4);
                return;
            }

            System.out.println(
                construirJson(ruta.toAbsolutePath().toString(), tipoDocumento, firmas, urlOcspArg, urlCrlArg)
            );
        } catch (Exception e) {
            System.err.println("Error al procesar documento: " + e.getClass().getName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    private static String construirJson(
        String archivo,
        String tipoDocumento,
        List<SignInfo> firmas,
        String urlOcspArg,
        String urlCrlArg
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"archivo\":").append(jsonStr(archivo)).append(",");
        sb.append("\"tipo\":").append(jsonStr(tipoDocumento)).append(",");
        sb.append("\"total_firmas\":").append(firmas != null ? firmas.size() : 0).append(",");
        sb.append("\"firmas\":[");

        if (firmas != null) {
            for (int i = 0; i < firmas.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                SignInfo info = firmas.get(i);
                Date fechaFirma = info.getSigningTime();

                sb.append("{");
                sb.append("\"algoritmo\":").append(jsonStr(info.getSignAlgorithm())).append(",");
                sb.append("\"fecha_firma\":").append(jsonStr(formatearFecha(fechaFirma))).append(",");
                sb.append("\"certificados\":[");

                X509Certificate[] certs = info.getCerts();
                if (certs != null) {
                    for (int j = 0; j < certs.length; j++) {
                        if (j > 0) {
                            sb.append(",");
                        }
                        X509Certificate cert = certs[j];
                        X509Certificate issuer = buscarEmisor(cert, certs, j);
                        boolean vigenteAhora = estaVigente(cert, null);
                        Boolean vigenteEnFirma = (fechaFirma != null) ? estaVigente(cert, fechaFirma) : null;

                        String ocspUrlEfectiva = (urlOcspArg != null) ? urlOcspArg : extraerUrlOcspAsn1(cert);
                        String ocspEstado = null;
                        String ocspError = null;
                        if (ocspUrlEfectiva != null && issuer != null) {
                            try {
                                ocspEstado = ValidadorOCSP.ValidarOCSP(cert, issuer, ocspUrlEfectiva);
                            } catch (Exception ex) {
                                ocspError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                            }
                        }

                        List<String> crlCandidatas = resolverCrlsCandidatas(cert, issuer, urlCrlArg);
                        Boolean revocadoPorCrl = null;
                        String crlConsultada = null;
                        List<String> crlErrores = new ArrayList<>();

                        for (String crlUrl : crlCandidatas) {
                            CrlCacheEntry entry = obtenerCrlConCache(crlUrl);
                            if (entry.error != null) {
                                crlErrores.add(crlUrl + " -> " + entry.error);
                                continue;
                            }
                            if (entry.crl != null) {
                                crlConsultada = crlUrl;
                                boolean estaRevocado = entry.crl.isRevoked(cert);
                                revocadoPorCrl = estaRevocado;
                                if (estaRevocado) {
                                    break;
                                }
                            }
                        }

                        String crlErrorResumen = crlErrores.isEmpty() ? null : String.join(" | ", crlErrores);

                        sb.append("{");
                        sb.append("\"subject\":").append(jsonStr(cert.getSubjectX500Principal().getName())).append(",");
                        sb.append("\"issuer\":").append(jsonStr(cert.getIssuerX500Principal().getName())).append(",");
                        sb.append("\"serial\":").append(jsonStr(cert.getSerialNumber().toString(16))).append(",");
                        sb.append("\"not_before\":").append(jsonStr(formatearFecha(cert.getNotBefore()))).append(",");
                        sb.append("\"not_after\":").append(jsonStr(formatearFecha(cert.getNotAfter()))).append(",");
                        sb.append("\"vigente_ahora\":").append(vigenteAhora).append(",");
                        sb.append("\"vigente_en_firma\":").append(vigenteEnFirma == null ? "null" : vigenteEnFirma).append(",");
                        sb.append("\"ocsp_url\":").append(jsonStr(ocspUrlEfectiva)).append(",");
                        sb.append("\"ocsp_respuesta\":").append(jsonStr(ocspEstado)).append(",");
                        sb.append("\"ocsp_error\":").append(jsonStr(ocspError)).append(",");
                        sb.append("\"crl_url_usada\":").append(jsonStr(crlConsultada)).append(",");
                        sb.append("\"revocado_crl\":").append(revocadoPorCrl == null ? "null" : revocadoPorCrl).append(",");
                        sb.append("\"crl_error\":").append(jsonStr(crlErrorResumen));
                        sb.append("}");
                    }
                }

                sb.append("]");
                sb.append("}");
            }
        }

        sb.append("]}");
        return sb.toString();
    }

    private static X509Certificate buscarEmisor(X509Certificate cert, X509Certificate[] cadena, int indiceActual) {
        if (indiceActual + 1 < cadena.length) {
            return cadena[indiceActual + 1];
        }
        for (X509Certificate candidato : cadena) {
            if (candidato.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                return candidato;
            }
        }
        return null;
    }

    private static boolean estaVigente(X509Certificate cert, Date fechaReferencia) {
        try {
            if (fechaReferencia == null) {
                cert.checkValidity();
            } else {
                cert.checkValidity(fechaReferencia);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String extraerUrlOcspAsn1(X509Certificate cert) {
        try {
            byte[] extBytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (extBytes == null) {
                return null;
            }
            ASN1OctetString octet = (ASN1OctetString) new ASN1InputStream(
                new ByteArrayInputStream(extBytes)
            ).readObject();
            if (octet == null) {
                return null;
            }
            ASN1Primitive aiaPrimitive = new ASN1InputStream(
                new ByteArrayInputStream(octet.getOctets())
            ).readObject();
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaPrimitive);
            if (aia == null) {
                return null;
            }
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                    GeneralName loc = ad.getAccessLocation();
                    if (loc != null && loc.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return loc.getName().toString();
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<String> resolverCrlsCandidatas(X509Certificate cert, X509Certificate issuer, String urlCrlArg) {
        Set<String> urls = new LinkedHashSet<>();
        if (urlCrlArg != null) {
            urls.add(urlCrlArg);
            return new ArrayList<>(urls);
        }

        String contexto = (
            cert.getIssuerX500Principal().getName() + " " +
            cert.getSubjectX500Principal().getName() + " " +
            (issuer != null ? issuer.getSubjectX500Principal().getName() : "")
        ).toUpperCase(Locale.ROOT);

        if (contexto.contains("BANCO CENTRAL")) {
            urls.add(ServicioCRL.BCE_CRL);
        }
        if (contexto.contains("SECURITY DATA")) {
            urls.add(ServicioCRL.SD_CRL1);
            urls.add(ServicioCRL.SD_CRL2);
            urls.add(ServicioCRL.SD_CRL3);
            urls.add(ServicioCRL.SD_CRL4);
            urls.add(ServicioCRL.SD_CRL5);
        }
        if (contexto.contains("CONSEJO DE LA JUDICATURA") || contexto.contains("JUDICATURA")) {
            urls.add(ServicioCRL.CJ_CRL);
        }
        if (contexto.contains("ANFAC")) {
            urls.add(ServicioCRL.ANFAC_CRL1);
            urls.add(ServicioCRL.ANFAC_CRL2);
        }
        if (contexto.contains("DIGERCIC") || contexto.contains("REGISTRO CIVIL")) {
            urls.add(ServicioCRL.DIGERCIC_CRL);
        }
        if (contexto.contains("UANATACA")) {
            urls.add(ServicioCRL.UANATACA_CRL1);
            urls.add(ServicioCRL.UANATACA_CRL2);
        }
        if (contexto.contains("DATIL")) {
            urls.add(ServicioCRL.DATIL_CRL);
        }
        if (contexto.contains("ARGOSDATA") || contexto.contains("ARGOS DATA")) {
            urls.add(ServicioCRL.ARGOSDATA_CRL);
        }
        if (contexto.contains("FIRMA SEGURA") || contexto.contains("FIRMASEGURA")) {
            urls.add(ServicioCRL.FIRMASEGURA_CRL);
        }
        if (contexto.contains("APP FIRMAS") || contexto.contains("APPFIRMAS")) {
            urls.add(ServicioCRL.APP_FIRMAS_CRL);
        }

        return new ArrayList<>(urls);
    }

    private static synchronized CrlCacheEntry obtenerCrlConCache(String url) {
        if (CRL_CACHE.containsKey(url)) {
            return CRL_CACHE.get(url);
        }
        try {
            X509CRL crl = ServicioCRL.downloadCrl(url);
            CrlCacheEntry entry = new CrlCacheEntry(crl, null);
            CRL_CACHE.put(url, entry);
            return entry;
        } catch (Exception ex) {
            CrlCacheEntry entry = new CrlCacheEntry(null, ex.getClass().getSimpleName() + ": " + ex.getMessage());
            CRL_CACHE.put(url, entry);
            return entry;
        }
    }

    private static String formatearFecha(Date fecha) {
        if (fecha == null) {
            return null;
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(fecha);
    }

    private static String jsonStr(String valor) {
        if (valor == null) {
            return "null";
        }
        return "\"" + esc(valor) + "\"";
    }

    private static String esc(String texto) {
        return texto
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
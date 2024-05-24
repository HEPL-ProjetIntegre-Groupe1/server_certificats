import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CertificateHandler {

    private final String caKeystorePath;
    private final String caKeystorePassword;
    private final String caKeyPassword;

    private final X500Name issuer = new X500Name("CN=Neverland Federal, OU=Neverland Federal, O=Neverland Federal, L=Neverland, ST=Neverland, C=NV");

    private final String issuedKeyStorePath = "../Keystore/issued.jks";
    private final String issuedKeystorePassword = "issued";

    public CertificateHandler(String caKeystorePath, String caKeystorePassword, String caKeyPassword) {
        // init bouncy castle
        Security.addProvider(new BouncyCastleProvider());
        this.caKeystorePath = caKeystorePath;
        this.caKeystorePassword = caKeystorePassword;
        this.caKeyPassword = caKeyPassword;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator pairGen  = KeyPairGenerator.getInstance("RSA", "BC");
        pairGen.initialize(2048);
        return pairGen.generateKeyPair();
    }

    public X509Certificate generateAndSignCertificate(KeyPair keyPair, String commonName, String organisationUnit, String organisation, String locality, String state, String country) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, UnrecoverableKeyException {
        // Création du certificat
        try {
            Calendar cal = Calendar.getInstance();
            Date start = cal.getTime();
            cal.add(Calendar.YEAR, 1);
            Date end = cal.getTime();

            X500Name issuedSubject = new X500Name("CN=" + commonName + ", OU=" + organisationUnit + ", O=" + organisation + ", L=" + locality + ", ST=" + state + ", C=" + country);

            BigInteger serial = new BigInteger(64, new SecureRandom());
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedSubject, keyPair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");


            // Recup de la clé privée du CA
            KeyStore keystoreCA = KeyStore.getInstance("JKS");
            keystoreCA.load(new java.io.FileInputStream(caKeystorePath), caKeystorePassword.toCharArray());
            PrivateKey caPrivateKey = (PrivateKey) keystoreCA.getKey("ca", caKeyPassword.toCharArray());
            X509Certificate caCert = (X509Certificate) keystoreCA.getCertificate("ca");

            ContentSigner signer = csBuilder.build(caPrivateKey);
            PKCS10CertificationRequest csr = p10Builder.build(signer);
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, start, end, csr.getSubject(), csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

            // Add Issuer cert identifier as Extension
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
            // Add Subject cert identifier as Extension
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            // verify the cert
            cert.verify(caCert.getPublicKey(), "BC");

            // export to issued keystore
            KeyStore issuedKeyStore = KeyStore.getInstance("JKS");
            issuedKeyStore.load(new FileInputStream(issuedKeyStorePath), issuedKeystorePassword.toCharArray());
            issuedKeyStore.setCertificateEntry(commonName, cert);
            issuedKeyStore.store(new java.io.FileOutputStream(issuedKeyStorePath), issuedKeystorePassword.toCharArray());

            return cert;
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
}

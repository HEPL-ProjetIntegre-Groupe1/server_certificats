import sun.security.x509.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateHandler {

    private final String caKeystorePath;
    private final String caKeystorePassword;
    private final String caKeyPassword;
    private static final long validity = 365L * 24 * 60 * 60 * 1000; // 1 an

    public CertificateHandler(String caKeystorePath, String caKeystorePassword, String caKeyPassword) {
        this.caKeystorePath = caKeystorePath;
        this.caKeystorePassword = caKeystorePassword;
        this.caKeyPassword = caKeyPassword;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator pairGen  = KeyPairGenerator.getInstance("RSA");
        pairGen.initialize(2048);
        return pairGen.generateKeyPair();
    }

    public X509Certificate generateAndSignCertificate(KeyPair keyPair, String commonName, String organisationUnit, String organisation, String locality, String state, String country) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, UnrecoverableKeyException {
        X500Name x500Name = new X500Name(commonName, organisationUnit, organisation, locality, state, country);
        X500Name issuer = new X500Name("CA", "Neverland Federal", "Neverland Federal", "Neverland", "Neverland", "NV");
        // get the ca issuer info
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.SUBJECT, x500Name);
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(new Date(), new Date(System.currentTimeMillis() + validity)));
        info.set(X509CertInfo.SERIAL_NUMBER, new sun.security.x509.SerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
        info.set(X509CertInfo.KEY, keyPair.getPublic());
        info.set(X509CertInfo.VERSION, new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));
        // algo de signature par defaut -> sera mis à jour
        AlgorithmId algo = new AlgorithmId(AlgorithmId.SHA256withECDSA_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        info.set(X509CertInfo.ISSUER, issuer);
        X509CertImpl cert = new X509CertImpl(info);

        // Signature du certificat avec la clé privée du CA
        // Recup de la clé privée du CA
        KeyStore keystoreCA = KeyStore.getInstance("JKS");
        keystoreCA.load(new java.io.FileInputStream(caKeystorePath), caKeystorePassword.toCharArray());
        PrivateKey caPrivateKey = (PrivateKey) keystoreCA.getKey("ca", caKeyPassword.toCharArray());
        // Signature du certificat
        cert.sign(caPrivateKey, "SHA256withRSA");
        // màj algorithm pour le certificat
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        // re-signature du certificat
        cert.sign(caPrivateKey, "SHA256withRSA");
        return cert;
    }
}

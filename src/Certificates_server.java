import SecuMessageDS.Message;
import serveurgenssl.LoggerDS;
import serveurgenssl.DefaultServerUI;
import serveurgenssl.ProtocoleReseauSSL;
import serveurgenssl.ThreadServeurSSL;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

public class Certificates_server implements ProtocoleReseauSSL{
    private final LoggerDS logger;
    private static final long validity = 365L * 24 * 60 * 60 * 1000; // 1 an
    private static final String keystorePath = "../Keystore/neverlandrootca.jks";
    private static final String keystorePassword = "neverlandrootca";
    private static final String keyPassword = "ca";


    public Certificates_server(LoggerDS logger) {
        this.logger = logger;
    }

    public static void main(String[] args) {
        DefaultServerUI ui = new DefaultServerUI("Certificates_server");
        Certificates_server protocole = new Certificates_server(ui);
        ThreadServeurSSL threadServeur = new ThreadServeurSSL(8044, "10.0.0.13", protocole, keystorePath, keystorePassword, keyPassword, 2, ui);
        ui.setThreadServeur(threadServeur);
        threadServeur.start();
    }

    public void communique (SSLSocket sslSocket, int numLog) {
        ObjectInputStream oiStream;
        ObjectOutputStream ooStream;
        Message requete;
        try {
            oiStream = new ObjectInputStream(sslSocket.getInputStream());
            ooStream = new ObjectOutputStream(sslSocket.getOutputStream());
        } catch (IOException ex) {
            logger.log("Thread Com "+ numLog,ex.getMessage());
            return;
        }
        // lecture message envoyé par le client
        try {
            requete = (Message) oiStream.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            logger.log("Thread Com "+ numLog,ex.getMessage());
            return;
        }
        // recup des infos nécessaires
        if (requete.type != 2){
            logger.log("Thread Com "+ numLog,"Message reçu inconnu (type != 2) : " +requete.getFromMessageList(0) );
            return;
        }
        String commonName = (String) requete.getFromMessageList(0);
        String organisationUnit = (String) requete.getFromMessageList(1);
        String organisation = (String) requete.getFromMessageList(2);
        String locality = (String) requete.getFromMessageList(3);
        String state = (String) requete.getFromMessageList(4);
        String country = (String) requete.getFromMessageList(5);

        // chargement du keystore CA
        KeyStore keystoreCA = null;
        try {
            keystoreCA = KeyStore.getInstance("JKS");
            keystoreCA.load(new java.io.FileInputStream(keystorePath), keystorePassword.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
            logger.log("Thread Com "+ numLog,ex.getMessage());
            return;
        }

        // Génération d'une paire de clés RSA 2048
        // execute la commande shell keytool pour générer un keystore avec une clé privée et un certificat
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec("keytool -genkeypair -dname \"CN=" + commonName+", OU=" + organisationUnit + ", O="
                    + organisation + ", L=" + locality + ", ST=" + state + ", C=" + country +
                    "\" -alias " + commonName + " -keyalg RSA -keysize 2048 -keystore tmp.jks");
            //
        } catch (IOException ex) {
            logger.log("Thread Com "+ numLog,ex.getMessage());
            return;
        }



















        // keytool -genkey -alias tmp -keyalg RSA -keysize 2048 -keystore tmp.jks









        CertAndKeyGen keyPair = initCertAndKeyGen(numLog, commonName, organisationUnit, organisation, locality, state, country);
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = generatePrivateKey(keyPair);
        if (privateKey == null) {
            return;
        }
        X509Certificate cert = generateCertificate(numLog, keyPair);

        // Création du certificat avec les infos du client, la clé publique et signé par la clé privée du serveur
        /*
            CertAndKeyGen keyPair = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
            X500Name x500Name = new X500Name(commonName, organisationUnit, organisation, locality, state, country);
            X509CertInfo info = new X509CertInfo();
            info.set(X509CertInfo.SUBJECT, x500Name);
            info.set(X509CertInfo.VALIDITY, new CertificateValidity(new Date(), new Date(System.currentTimeMillis() + validity)));
            info.set(X509CertInfo.SERIAL_NUMBER, new sun.security.x509.SerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
            info.set(X509CertInfo.KEY, keyPair.getPublicKey());
            info.set(X509CertInfo.VERSION, new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));
            AlgorithmId algo = new AlgorithmId(AlgorithmId.SHA256withECDSA_oid);
            keyPair.generate(2048);
            PrivateKey privateKey = keyPair.getPrivateKey();
            X509Certificate cert = keyPair.getSelfCertificate(x500Name, new Date(), validity);
            // Signature du certificat avec la clé privée du CA
            // Recup de la clé privée du CA
            PrivateKey caPrivateKey = (PrivateKey) keystoreCA.getKey("ca", keyPassword.toCharArray());
            // Recup du certificat du CA
            Certificate caCert = keystoreCA.getCertificate("ca");
            // Signature du certificat
            cert
        */


        logger.log("Thread Com "+ numLog,"Message reçu : " +requete.getFromMessageList(0) );

        // traitement de la requete
        Message reponse = new Message(0,true);
        reponse.addToMessageList("ok");
        // envoi de la réponse
        try {
            ooStream.writeObject(reponse);
        } catch (IOException ex) {
            logger.log("Thread Com "+ numLog,ex.getMessage());
            return;
        }
    }

    private CertAndKeyGen initCertAndKeyGen(int numLog, String commonName, String organisationUnit, String organisation, String locality, String state, String country) {
        CertAndKeyGen pairGen = null;
        try {
            pairGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
            X500Name x500Name = new X500Name(commonName, organisationUnit, organisation, locality, state, country);
            // get the ca issuer info
            X500Name issuer = new X500Name("CN=ca");
            X509CertInfo info = new X509CertInfo();
            info.set(X509CertInfo.SUBJECT, x500Name);
            info.set(X509CertInfo.VALIDITY, new CertificateValidity(new Date(), new Date(System.currentTimeMillis() + validity)));
            info.set(X509CertInfo.SERIAL_NUMBER, new sun.security.x509.SerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
            info.set(X509CertInfo.KEY, pairGen.getPublicKey());
            info.set(X509CertInfo.VERSION, new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));
            AlgorithmId algo = new AlgorithmId(AlgorithmId.SHA256withECDSA_oid);

            pairGen.generate(2048);
            return pairGen;
        } catch (Exception e) {
            logger.log("Thread Com " + numLog, e.getMessage());
            return null;
        }
    }

    private PrivateKey generatePrivateKey(CertAndKeyGen pairGen) {
        return pairGen.getPrivateKey();
    }


    private X509Certificate generateCertificate(int numLog, CertAndKeyGen pairGen) {
        try {
            return pairGen.getSelfCertificate(new X500Name("CN=Test"), new Date(), validity);
        } catch (Exception e) {
            logger.log("Thread Com " + numLog, e.getMessage());
            return null;
        }
    }

    private X509Certificate signCertificate(int numLog, X509Certificate cert, PrivateKey caPrivateKey, Certificate caCert) {
        try {
            // cert(caPrivateKey, "SHA256withRSA");
        } catch (Exception e) {
            logger.log("Thread Com " + numLog, e.getMessage());
            return null;
        }
        return cert;
    }

    @Override
    public void arret() {
        // nothing to do
    }
}



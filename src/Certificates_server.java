import SecuMessageDS.Message;
import serveurgenssl.LoggerDS;
import serveurgenssl.ProtocoleReseauSSL;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificates_server implements ProtocoleReseauSSL{
    private final LoggerDS logger;
    private final CertificateHandler certificateHandler;



    public Certificates_server(LoggerDS logger, String keystorePath, String keystorePassword, String keyPassword) {
        this.logger = logger;
        this.certificateHandler = new CertificateHandler(keystorePath, keystorePassword, keyPassword);
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

        // Génération d'une paire de clés RSA 2048
        KeyPair keyPair = null;
        try {
            keyPair = certificateHandler.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.log("Thread Com "+ numLog,e.getMessage());
        }
        if (keyPair == null) {
            return;
        }
        logger.log("Thread Com "+ numLog,"Paire de clés générée");
        // Génération et signature du certificat
        X509Certificate cert = null;
        try {
            cert = certificateHandler.generateAndSignCertificate(keyPair, commonName, organisationUnit, organisation, locality, state, country);
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException |
                 SignatureException | InvalidKeyException | NoSuchProviderException | UnrecoverableKeyException e) {
            logger.log("Thread Com "+ numLog,e.getMessage());
        }
        if (cert == null) {
            return;
        }
        logger.log("Thread Com "+ numLog,"Certificat généré et signé");
        PrivateKey privateKey = keyPair.getPrivate();
        // Certificat généré et signé
        // Reste à l'envoyer au client
        Message reponse = new Message(2,true);
        reponse.addToMessageList(cert);
        reponse.addToMessageList(privateKey);
        // envoi de la réponse
        reponse.toStream(ooStream);
        logger.log("Thread Com "+ numLog,"Certificat envoyé");

    }

    @Override
    public void arret() {
        // nothing to do
    }

    /* Code douteux
    // execute la commande shell keytool pour générer un keystore avec une clé privée et un certificat
    Runtime runtime = Runtime.getRuntime();
    try {
        // exporter le certificat du CA pour pouvoir l'ajouter à la chaine de certificat
        runtime.exec("keytool -export -alias ca -file ca.crt -keystore ../../../Keystore/neverlandrootca.jks -storepass neverlandrootca");

        runtime.exec("keytool -genkeypair -dname \"CN=" + commonName+", OU=" + organisationUnit + ", O="
                + organisation + ", L=" + locality + ", ST=" + state + ", C=" + country +
                "\" -alias " + commonName + " -keyalg RSA -keysize 2048 -keystore ../../../Keystore/tmp.jks -storepass tmptmp -keypass tmptmp -validity 365");
        // exemple de commande shell : keytool -genkeypair -dname "CN=Test, OU=Test, O=Test, L=Test, ST=Test, C=FR" -alias tmp -keyalg RSA -keysize 2048 -keystore tmp.jks -storepass tmp -keypass tmp -validity 365
        // maintenant on a un keystore tmp.jks avec une clé privée et un certificat
        // il faut maintenant signer ce certificat avec la clé privée du CA
        // -> creation d'une csr
        runtime.exec("keytool -certreq -alias " + commonName + " -file tmp.csr -keystore /home/user/Keystore/tmp.jks");
        // il faut maintenant signer ce certificat avec la clé privée du CA
        runtime.exec("keytool -gencert -alias ca -infile tmp.csr -outfile tmp.crt -keystore /home/user/Keystore/neverlandrootca.jks -storepass neverlandrootca -keypass ca -validity 365");
        // il faut maintenant importer le certificat signé dans le keystore tmp.jks et ajouter le certificat du CA à la chaine de certificat
        runtime.exec("keytool -import -alias ca -file ca.crt -keystore tmp.jks -storepass tmp");
        runtime.exec("keytool -import -alias " + commonName + " -file tmp.crt -keystore tmp.jks -storepass tmp");
        // il faut maintenant exporter le certificat signé avec la chaine de certificat


    } catch (IOException ex) {
        logger.log("Thread Com "+ numLog,ex.getMessage());
        return;
    }
    */
}



package com.neverland.certificates.client;

import SecuMessageDS.Message;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;

public class ClientCertificat {
    private final String serverName = "10.0.0.13";
    private final int serverPort = 8044;


    private final String keystorePath = "../keystores/client_certificates.jks";
    private final String keystorePassword = "client_certificates";
    private final String keyPassword = "client_certificates";

    private SSLSocketFactory sslSocketFactory;
    private SSLSocket socketClient;

    public static void main(String[] args) {
        System.out.println("Hello world!");
        ClientCertificat client = new ClientCertificat();
        client.getCertifiedKeyPair();
    }

    public ClientCertificat(){

    }
    public void getCertifiedKeyPair(){
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
            // SSLContext
            SSLContext sslCtx = SSLContext.getInstance("TLS");
            KeyManagerFactory keyMF = KeyManagerFactory.getInstance("SunX509");
            keyMF.init(keystore, keyPassword.toCharArray());
            TrustManagerFactory trustMF = TrustManagerFactory.getInstance("SunX509");
            trustMF.init(keystore);
            sslCtx.init(keyMF.getKeyManagers(), trustMF.getTrustManagers(), null);
            // SSLServerSocketFactory
            sslSocketFactory = sslCtx.getSocketFactory();
            socketClient = (SSLSocket) sslSocketFactory.createSocket(serverName, serverPort);

            ObjectOutputStream ooStream = new ObjectOutputStream(socketClient.getOutputStream());
            ObjectInputStream oiStream = new ObjectInputStream(socketClient.getInputStream());
            Message requete = new Message(2);
            requete.addToMessageList("jean dupont");
            requete.addToMessageList("neverland inc.");
            requete.addToMessageList("service technique");
            requete.addToMessageList("neverland city");
            requete.addToMessageList("neverland state");
            requete.addToMessageList("neverland");
            requete.toStream(ooStream);
            System.out.println("Message sent");

            Message response = Message.fromStream(oiStream);
            System.out.println("Response received");
            X509Certificate certificate = (X509Certificate) response.getFromMessageList(0);
            PrivateKey privateKey = (PrivateKey) response.getFromMessageList(1);
            System.out.println(certificate);
            System.out.println(privateKey);

            requete = new Message(2,true);
            requete.toStream(ooStream);
        } catch (UnrecoverableKeyException | CertificateException | KeyStoreException | IOException |
                 NoSuchAlgorithmException | KeyManagementException e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
}
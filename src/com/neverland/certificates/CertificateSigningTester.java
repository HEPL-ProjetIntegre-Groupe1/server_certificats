package com.neverland.certificates;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertificateSigningTester {
    private static final String caKeystorePath = "../Keystore/neverlandrootca.jks";
    private static final String caKeystorePassword = "neverlandrootca";
    private static final String caKeyPassword = "ca";
    private static final String issuedKeystorePath = "../Keystore/issued.jks";
    private static final String issuedKeystorePassword = "issued";
    
    public static void main(String[] args) {
        System.out.println("Hello, Programmers!");
        CertificateHandler certificateHandler = new CertificateHandler();
        certificateHandler.setCaKeystore(caKeystorePath, caKeystorePassword, caKeyPassword);
        certificateHandler.setIssuedKeystore(issuedKeystorePath, issuedKeystorePassword);
        try {
            KeyPair keyPair = certificateHandler.generateKeyPair();
            X509Certificate certificate = certificateHandler.generateAndSignCertificate(keyPair, "CN", "OU", "O", "L", "S", "C");
            System.out.println(certificate);
            System.out.println(keyPair.getPrivate());
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
}

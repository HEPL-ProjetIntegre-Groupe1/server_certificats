package com.neverland.certificates;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertificateSigningTester {
    private static final String keystorePath = "../Keystore/neverlandrootca.jks";
    private static final String keystorePassword = "neverlandrootca";
    private static final String keyPassword = "ca";
    public static void main(String[] args) {
        System.out.println("Hello, Programmers!");
        CertificateHandler certificateHandler = new CertificateHandler(keystorePath, keystorePassword, keyPassword);
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

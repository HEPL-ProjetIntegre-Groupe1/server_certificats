package com.neverland.certificates;

import serveurgenssl.DefaultServerUI;
import serveurgenssl.ThreadServeurSSL;

public class StarterCertificateServer {
    private static final String ip = "10.0.0.13";
    private static final int port = 8044;
    private static final String caKeystorePath = "../Keystore/neverlandrootca.jks";
    private static final String caKeystorePassword = "neverlandrootca";
    private static final String caKeyPassword = "ca";
    private static final String issuedKeystorePath = "../Keystore/issued.jks";
    private static final String issuedKeystorePassword = "issued";

    public static void main(String[] args) {
        DefaultServerUI ui = new DefaultServerUI("com.neverland.certificates.Certificates_server");
        CertificatesProtocol protocole = new CertificatesProtocol(ui);
        protocole.setCAKeystore(caKeystorePath, caKeystorePassword, caKeyPassword);
        protocole.setIssuedKeystore(issuedKeystorePath, issuedKeystorePassword);
        ThreadServeurSSL threadServeur = new ThreadServeurSSL(port, ip, protocole, caKeystorePath, caKeystorePassword, caKeyPassword, 2, ui);
        ui.setThreadServeur(threadServeur);
    }
}

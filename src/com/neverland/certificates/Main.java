package com.neverland.certificates;

import serveurgenssl.DefaultServerUI;
import serveurgenssl.ThreadServeurSSL;

public class Main {
    private static final String keystorePath = "../Keystore/neverlandrootca.jks";
    private static final String keystorePassword = "neverlandrootca";
    private static final String keyPassword = "ca";
    private static final String ip = "10.0.0.13";
    private static final int port = 8044;

    public static void main(String[] args) {
        DefaultServerUI ui = new DefaultServerUI("com.neverland.certificates.Certificates_server");
        Certificates_server protocole = new Certificates_server(ui, keystorePath, keystorePassword, keyPassword);
        ThreadServeurSSL threadServeur = new ThreadServeurSSL(port, ip, protocole, keystorePath, keystorePassword, keyPassword, 2, ui);
        ui.setThreadServeur(threadServeur);
        threadServeur.start();
    }
}

package com.neverland.certificates.client;

import javax.swing.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class ClientUI {
    private JTextField tfCommonName;
    private JTextField tfOrganisationUnit;
    private JTextField tfOrganisation;
    private JTextField tfLocality;
    private JTextField tfState;
    private JTextField tfCountry;
    private JButton buttonAsk;
    private JTextArea taReponse;
    private JPanel panel;
    private ClientCertificat clientCertificat;
    public ClientUI() {
        JFrame frame = new JFrame("Client Certificate");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setContentPane(panel);
        frame.setSize(400, 400);
        frame.setVisible(true);
        clientCertificat = new ClientCertificat();
        buttonAsk.addActionListener(e -> {
            String commonName = tfCommonName.getText();
            String organisationUnit = tfOrganisationUnit.getText();
            String organisation = tfOrganisation.getText();
            String locality = tfLocality.getText();
            String state = tfState.getText();
            String country = tfCountry.getText();
            clientCertificat.getCertifiedKeyPair(commonName, organisationUnit, organisation, locality, state, country);
            X509Certificate certificate = clientCertificat.getCertificate();
            PrivateKey privateKey = clientCertificat.getPrivateKey();
            taReponse.setText("Certificat généré");
            taReponse.append("\n" + certificate);
            taReponse.append("\n" + privateKey);
            clientCertificat.saveCertificateAndPrivateKey(commonName, certificate, privateKey);
            taReponse.append("\nCertificat et clé privée sauvegardés");
        });
    }
}

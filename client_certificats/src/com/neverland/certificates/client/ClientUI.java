package com.neverland.certificates.client;

import javax.swing.*;

public class ClientUI {
    private JTextField tfCommonName;
    private JTextField tfOrganisationUnit;
    private JTextField tfOrganisation;
    private JTextField tfLocality;
    private JTextField tfState;
    private JTextField tfCountry;
    private JButton buttonAsk;
    private JTextArea taReponse;
    private ClientCertificat clientCertificat;
    public ClientUI() {
        JFrame frame = new JFrame("Client Certificate");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);
        frame.setVisible(true);
        clientCertificat = new ClientCertificat();
    }
}

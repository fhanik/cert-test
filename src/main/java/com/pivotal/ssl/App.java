package com.pivotal.ssl;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(App.class.getResourceAsStream("/cert.pem"));
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(App.class.getResourceAsStream("/DigiCertCA.crt"));
        X509Certificate self = (X509Certificate)cf.generateCertificate(App.class.getResourceAsStream("/self/server.crt"));

        X509Certificate starProdDmzCert = (X509Certificate)cf.generateCertificate(App.class.getResourceAsStream("/star_proddmz_cf_corelogic_net.crt"));

        //yes, we can validate
        cert.verify(caCert.getPublicKey());

        //normal cacerts
        File keystoreFile = new File("src/main/resources/cacerts");
        verifyStoreCerts("cert.pem", keystoreFile, cert);

        //digicertCA imported
        keystoreFile = new File("src/main/resources/cacerts_and_digicert");
        verifyStoreCerts("cert.pem", keystoreFile, cert);

        //the cert itself import
        keystoreFile = new File("src/main/resources/cacerts_and_cert_installed");
        verifyStoreCerts("cert.pem", keystoreFile, cert);

        //the self signed itself import
        keystoreFile = new File("src/main/resources/cacerts_and_self_signed");
        verifyStoreCerts("self signed server.crt", keystoreFile, self);

        //normal cacerts
        keystoreFile = new File("src/main/resources/cacerts");
        verifyStoreCerts("star_proddmz_cf_corelogic_net.crt", keystoreFile, starProdDmzCert);

        //digicertCA imported
        keystoreFile = new File("src/main/resources/cacerts_and_digicert");
        verifyStoreCerts("star_proddmz_cf_corelogic_net.crt", keystoreFile, starProdDmzCert);

        //the cert itself import
        keystoreFile = new File("src/main/resources/cacerts_and_star_proddmz");
        verifyStoreCerts("star_proddmz_cf_corelogic_net.crt", keystoreFile, starProdDmzCert);


    }


    public static boolean verifyStoreCerts(String name, File keystoreFile, X509Certificate cert) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm());

        InputStream is = new FileInputStream(keystoreFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "changeit";
        keystore.load(is, password.toCharArray());

        tmf.init(keystore);


        Enumeration enumeration = keystore.aliases();
        boolean keyvalidated = false;
        boolean servertrusted = false;
        while(enumeration.hasMoreElements()) {
            String alias = (String)enumeration.nextElement();
            //System.out.println("alias name: " + alias);
            Certificate certificate = keystore.getCertificate(alias);
            //System.out.println(certificate.toString());
            try {
                cert.verify(certificate.getPublicKey());
                keyvalidated = true;
                System.out.println("VERIFIED["+name+"] against public key with alias:"+alias);
                break;
            } catch (Exception x) {
                //System.err.println("Not verified[\"+name+\"] with alias:"+alias+" \n"+x.getMessage());
            }
        }

        for (TrustManager tm : tmf.getTrustManagers()) {
            X509TrustManager xtm = (X509TrustManager)tm;
            try {
                xtm.checkServerTrusted(new X509Certificate[] {cert}, "RSA");
                servertrusted = true;
                System.out.println("VERIFIED[" + name + "] is a trusted cert in keystore:" + keystoreFile.getName());
            } catch (CertificateException e) {

            }
        }
        return keyvalidated & servertrusted;
    }




}

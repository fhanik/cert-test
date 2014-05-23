package com.pivotal.ssl;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
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

        //yes, we can validate
        cert.verify(caCert.getPublicKey());

        //normal cacerts
        File file = new File("src/main/resources/cacerts");
        verifyStoreCerts("digiSignedCertOnDefaultCACERTS", file, cert);

        //digicertCA imported
        file = new File("src/main/resources/cacerts_and_digicert");
        verifyStoreCerts("digiSignedCertWithCAImported", file, cert);

        //the cert itself import
        file = new File("src/main/resources/cacerts_and_cert_installed");
        verifyStoreCerts("digiSignedCertWithCertImported", file, cert);

        //the self signed itself import
        file = new File("src/main/resources/cacerts_and_self_signed");
        verifyStoreCerts("SelfSignedCertWithCertImported", file, self);
    }


    public static boolean verifyStoreCerts(String name, File file, X509Certificate cert) throws Exception {
        InputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "changeit";
        keystore.load(is, password.toCharArray());

        Enumeration enumeration = keystore.aliases();
        boolean validated = false;
        while(enumeration.hasMoreElements()) {
            String alias = (String)enumeration.nextElement();
            //System.out.println("alias name: " + alias);
            Certificate certificate = keystore.getCertificate(alias);
            //System.out.println(certificate.toString());
            try {
                cert.verify(certificate.getPublicKey());
                validated = true;
                System.out.println("VERIFIED["+name+"] with alias:"+alias);
                break;
            } catch (Exception x) {
                //System.err.println("Not verified[\"+name+\"] with alias:"+alias+" \n"+x.getMessage());
            }
        }
        return validated;
    }


}

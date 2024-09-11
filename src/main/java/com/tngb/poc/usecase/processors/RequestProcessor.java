package com.tngb.poc.usecase.processors;

import com.tngb.poc.usecase.utils.Utils;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

@Component
public class RequestProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(RequestProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {
        String body = exchange.getIn().getBody(String.class);
        byte[] bodyBytes = Base64.getDecoder().decode(body);

        String privateKeyPath = exchange.getProperty("privateKeyPath", String.class);
        String privateKeyPassword = exchange.getProperty("privateKeyPassword", String.class);

        PrivateKey privateKey = Utils.getPrivateKey(privateKeyPath, privateKeyPassword);
        PublicKey publicKey = Utils.getPublicKey(privateKeyPath, privateKeyPassword);
        PGPPublicKey pgpPublicKey = Utils.getPGPPublicKey(publicKey);
        PGPPrivateKey pgpPrivateKey = Utils.getPGPPrivateKey(privateKey, pgpPublicKey);
        String plainBody = Utils.decryptDataWithPGP(pgpPrivateKey, bodyBytes);
        logger.info("Decrypted Request Body :: {}", plainBody);

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(plainBody.getBytes()));
        doc.getDocumentElement().normalize();

        String orgContentEncoded = doc.getElementsByTagName("OrgContent").item(0).getTextContent();
        logger.info("OrgContent Encoded Value :: {}", orgContentEncoded);
        byte[] orgContentDecodedBytes = Base64.getDecoder().decode(orgContentEncoded);


        String signatureEncoded = doc.getElementsByTagName("Signature").item(0).getTextContent();
        logger.info("Signature Encoded Value :: {}", signatureEncoded);
        byte[] signatureDecodedBytes = Base64.getDecoder().decode(signatureEncoded);

        String certificateEncoded = doc.getElementsByTagName("Certificate").item(0).getTextContent();
        logger.info("Certificate Encoded Value :: {}", certificateEncoded);
        byte[] certificateDecodedBytes = Base64.getDecoder().decode(certificateEncoded);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(certificateDecodedBytes));

        logger.info("Sending orgContent for Verification with Signature!!");
        boolean isVerified = Utils.verifySignature(orgContentDecodedBytes, signatureDecodedBytes, certificate);
        if(isVerified) {
            logger.info("Signature Verified with the Original Content");
            logger.info("Plain Original Content :: {}", Strings.fromByteArray(orgContentDecodedBytes));
        } else {
            logger.info("Signature Not Verified with the Original Content");
        }
    }
}

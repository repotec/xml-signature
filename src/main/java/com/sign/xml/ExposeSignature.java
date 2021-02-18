package com.sign.xml;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Document;

@SuppressWarnings("deprecation")
public class ExposeSignature {
    private static final String PRIVATE_KEY_ALIAS = "pkcs7-key-alias";
    private static final String PRIVATE_KEY_PASS = "pkcs7-password";
    private static final String KEY_STORE_PASS = "pkcs7-password";
    private static final String KEY_STORE_TYPE = "JKS";
    
    private static final String PATH_TO_KEYSTORE = "/pkcs7.keystore";
    private static final String XML_PATH = "/payment-info-response.xml";
    private static final String XML_SIGN_PATH_NAME = "payment-info-response-signed.xml";
    
    private static final String ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";      //RSA+SHA256
    private static final String SIGN_TYPE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";  //enveloped

    
    public static void main(String[] args) throws Exception {
    	ByteArrayOutputStream output = signFile(getFileFromResourceAsStream(XML_PATH), getFileFromResourceAsStream(PATH_TO_KEYSTORE));
        writeSignXMLDocument(output, XML_SIGN_PATH_NAME);
    }

    
    public static ByteArrayOutputStream signFile(InputStream xmlFile, InputStream privateKeyFile) throws Exception {
        final Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlFile);
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");
        final KeyStore keyStore = loadKeyStore(privateKeyFile);
        final XMLSignature xmlSignature = new XMLSignature(doc, null, ALGORITHM);
        final Transforms transforms = new Transforms(doc);
        
        transforms.addTransform(SIGN_TYPE);
        xmlSignature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        
        final Key privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
        final X509Certificate x509Cert = (X509Certificate)keyStore.getCertificate(PRIVATE_KEY_ALIAS);
        
        xmlSignature.addKeyInfo(x509Cert);
        xmlSignature.addKeyInfo(x509Cert.getPublicKey());
        xmlSignature.sign(privateKey);
        
        doc.getDocumentElement().appendChild(xmlSignature.getElement());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalizeSubtree(doc));
        System.out.println("file has been signed...");
        
        return outputStream;
    }
   
    private static KeyStore loadKeyStore(InputStream fileInputStream) throws Exception {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(fileInputStream, KEY_STORE_PASS.toCharArray());
            return keyStore;
        }
        finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }


    private static void writeSignXMLDocument(ByteArrayOutputStream signedOutputStream, String fileName) throws IOException {
    	String resources = "./src/main/resources/";
    	
        final OutputStream fileOutputStream = new FileOutputStream(resources + fileName);
        try {
            fileOutputStream.write(signedOutputStream.toByteArray());
            fileOutputStream.flush();
        }
        finally {
            IOUtils.closeQuietly(fileOutputStream);
        }
    }
    
    public static InputStream getFileFromResourceAsStream(String fileName) {
        InputStream inputStream = ExposeSignature.class.getResourceAsStream(fileName);
        if (inputStream == null) 
            throw new IllegalArgumentException("file not found! " + fileName);
         else 
            return inputStream;
    }
}

package org.jscep.client;

import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.Capability;
import org.junit.Test;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

/**
 * This isn't really a test, but it shows how to use the API.
 */
public class KeyStoreExampleClientTest extends ScepServerSupport {
    @Test
    public void testExample() throws Exception {
        // For the sake of simplicity, we use an optimistic verifier. This has
        // no
        // place in production code.
        DefaultCallbackHandler handler = new DefaultCallbackHandler(
                new OptimisticCertificateVerifier());
        Client client = new Client(getUrl(), handler);
        // Get the capabilities of the SCEP server
        Capabilities caps = client.getCaCapabilities();

        // We construct a Bouncy Castle digital signature provider early on,
        // so it can be reused later.
        JcaContentSignerBuilder signerBuilder;
        if (caps.contains(Capability.SHA_1)) {
            signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        } else {
            signerBuilder = new JcaContentSignerBuilder("MD5withRSA");
        }

        // The following variables are used to represent the SCEP client
        KeyPair idPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        X500Name issuer = new X500Name("CN=entity");
        BigInteger serial = new BigInteger(16, new SecureRandom());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, -1);
        Date notBefore = cal.getTime();
        cal.add(Calendar.DATE, 2);
        Date notAfter = cal.getTime();
        X500Name subject = issuer;
        PublicKey publicKey = idPair.getPublic();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        X509CertificateHolder idHolder = certBuilder.build(signerBuilder
                .build(idPair.getPrivate()));
        // Convert Bouncy Castle representation of X509Certificate into
        // something usable
        X509Certificate id = (X509Certificate) CertificateFactory.getInstance(
                "X509").generateCertificate(
                new ByteArrayInputStream(idHolder.getEncoded()));

        // The following variables are used to represent the entity being
        // enrolled
        X500Name entityName = new X500Name("CN=entity");
        KeyPair entityPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance(entityPair.getPublic().getEncoded());
        // Generate the certificate signing request
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                entityName, publicKeyInfo);
        // SCEP servers usually require a challenge password
        csrBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(new String("password".toCharArray())));
        ContentSigner signer = signerBuilder.build(entityPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        // Send the enrollment request
        EnrollmentResponse response = client
                .enrol(id, idPair.getPrivate(), csr);
        if (response.isFailure()) {
            // Our request was rejected!
            System.out.println("Failed!");
        } else if (response.isPending()) {
            // The server hasn't enrolled us, but we should try again.
            System.out.println("Pending!");

            X500Principal entityPrincipal = new X500Principal(
                    entityName.getEncoded());
            // We should deal with the response to the poll too. Since this a
            // short-lived
            // test, we conveniently stop processing here. Usually you'd
            // schedule the poll
            // to run at some point in the future.

            // It isn't a requirement to use the same ID and private key.
            response = client.poll(id, idPair.getPrivate(), entityPrincipal,
                    response.getTransactionId());
        } else if (response.isSuccess()) {
            // The entity has been enrolled
            System.out.println("Success!");

            // Convert the store to a certificate chain
            CertStore store = response.getCertStore();
            Collection<? extends Certificate> certs = store
                    .getCertificates(null);
            Certificate[] chain = new Certificate[certs.size()];

            int i = 0;
            for (Certificate certificate : certs) {
                chain[i++] = certificate;
            }

            // Store the entity key and certificate in a key store
            KeyStore entityStore = KeyStore.getInstance("JKS");
            entityStore.load(null, null);
            entityStore.setKeyEntry("entity", entityPair.getPrivate(),
                    "secret".toCharArray(), chain);
            entityStore.store(new ByteArrayOutputStream(),
                    "secret".toCharArray());
        }
    }
}

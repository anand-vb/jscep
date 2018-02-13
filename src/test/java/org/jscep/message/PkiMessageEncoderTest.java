package org.jscep.message;

import junit.framework.Assert;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.util.X509Certificates;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.spongycastle.asn1.*;
import org.spongycastle.asn1.cms.ContentInfo;
import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.cms.SignedData;
import org.spongycastle.asn1.cms.SignerInfo;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.*;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.util.Store;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class PkiMessageEncoderTest {
    @Parameters
    public static Collection<Object[]> getParameters() throws Exception {
        List<Object[]> params = new ArrayList<Object[]>();

        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        TransactionId transId = TransactionId.createTransactionId();
        Nonce recipientNonce = Nonce.nextNonce();
        Nonce senderNonce = recipientNonce;
        X500Name issuer = new X500Name("CN=CA");
        X500Name subject = new X500Name("CN=Client");
        IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
        BigInteger serial = BigInteger.ONE;
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);
        PKCS10CertificationRequest csr = getCsr(new X500Principal("CN=Client"),
                pair.getPublic(), pair.getPrivate(), "password".toCharArray());
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
                .build(pair.getPrivate());
        X509Certificate cert = X509Certificates.createEphemeral(
                new X500Principal("CN=client"), pair);
        Store certs = new JcaCertStore(Collections.singleton(cert));
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()).build(
                sha1Signer, cert));
        gen.addCertificates(certs);
        CMSTypedData msg = new CMSAbsentContent();
        CMSSignedData sigData = gen.generate(msg, false);

        params.add(new Object[] { new GetCert(transId, senderNonce, iasn) });
        params.add(new Object[] { new GetCertInitial(transId, senderNonce, ias) });
        params.add(new Object[] { new GetCrl(transId, senderNonce, iasn) });
        params.add(new Object[] { new PkcsReq(transId, senderNonce, csr) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce, sigData) });
        params.add(new Object[] { new CertRep(transId, senderNonce,
                recipientNonce, FailInfo.badAlg) });

        return params;
    }

    private final PkiMessage<?> message;

    public PkiMessageEncoderTest(PkiMessage<?> message) {
        this.message = message;
    }

    @Test
    public void simpleTestDES() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("DES");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestTripleDES() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("DESede");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES192() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_192");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES256() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_256");
        assertEquals(message, actual);
    }
    
    @Test
    public void simpleTestAES128() throws Exception {
    	PkiMessage<?> actual = encodeAndDecodeEnvelope("AES_128");
        assertEquals(message, actual);
    }

    @Test
    public void simpleTestAES() throws Exception {
        PkiMessage<?> actual = encodeAndDecodeEnvelope("AES");
        assertEquals(message, actual);
    }

    @Test
    public void invalidSignatureTest() throws Exception {
        KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate ca = X509Certificates.createEphemeral(
                new X500Principal("CN=CA"), caPair);

        KeyPair clientPair = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
        X509Certificate client = X509Certificates.createEphemeral(
                new X500Principal("CN=Client"), clientPair);

        // Everything below this line only available to client
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca,
                "DES");
        PkiMessageEncoder encoder = new PkiMessageEncoder(
                clientPair.getPrivate(), client, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(ca,
                caPair.getPrivate());

        PkiMessageDecoder decoder = new PkiMessageDecoder(client, envDecoder);

        CMSSignedData encodedMessage = encoder.encode(message);

        // modifify the signature
        CMSSignedData encodedMessage2 = modifySignature(encodedMessage);
        try{
            decoder.decode(encodedMessage2);
            Assert.fail("decoding exception expected");
        }catch(MessageDecodingException e)
        {
            assertEquals("decoding exception", "pkiMessage verification failed.", e.getMessage());
        }
    }

    private static PKCS10CertificationRequest getCsr(X500Principal subject,
            PublicKey pubKey, PrivateKey priKey, char[] password)
            throws GeneralSecurityException, IOException {
        DERPrintableString cpSet = new DERPrintableString(new String(password));
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                X500Name.getInstance(subject.getEncoded()), pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                cpSet);

        return builder.build(signer);
    }

    private static CMSSignedData modifySignature(CMSSignedData sd)
    throws CMSException
    {
        ContentInfo ci = sd.toASN1Structure();
        SignedData content = (SignedData) ci.getContent();
        SignerInfo si = (SignerInfo) content.getSignerInfos().getObjectAt(0);

        byte[] signature = si.getEncryptedDigest().getOctets();
        int index = signature.length - 10;
        signature[index] = (byte) (signature[index] + 1);

        ASN1OctetString signature2 = new DEROctetString(signature);
        SignerInfo si2 = new SignerInfo(
                si.getSID(),
                si.getDigestAlgorithm(),
                si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(),
                signature2,
                si.getUnauthenticatedAttributes());
        ASN1Set signerInfos2 = new DERSet(si2);

        SignedData content2 = new SignedData(
                content.getDigestAlgorithms(),
                content.getEncapContentInfo(),
                content.getCertificates(),
                content.getCRLs(),
                signerInfos2);

        ContentInfo ci2 = new ContentInfo(ci.getContentType(), content2);
        return new CMSSignedData(ci2);
    }
    
    public PkiMessage<?> encodeAndDecodeEnvelope(String cipherAlgorithm) throws Exception{
    	KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate ca = X509Certificates.createEphemeral(
                new X500Principal("CN=CA"), caPair);

        KeyPair clientPair = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
        X509Certificate client = X509Certificates.createEphemeral(
                new X500Principal("CN=Client"), clientPair);

        // Everything below this line only available to client
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca,
                cipherAlgorithm);
        PkiMessageEncoder encoder = new PkiMessageEncoder(
                clientPair.getPrivate(), client, envEncoder);

        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(ca,
                caPair.getPrivate());
        PkiMessageDecoder decoder = new PkiMessageDecoder(client, envDecoder);

        PkiMessage<?> actual = decoder.decode(encoder.encode(message));

        return actual;
    	
    }
}

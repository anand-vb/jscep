package org.jscep.message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.cms.*;
import org.spongycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.spongycastle.operator.OutputEncryptor;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.spongycastle.cms.CMSAlgorithm.*;

/**
 * This class is used for enveloping and encrypting a <tt>messageData</tt> to
 * produce the <tt>pkcsPkiEnvelope</tt> part of a SCEP secure message object.
 * 
 * @see PkcsPkiEnvelopeDecoder
 */
public final class PkcsPkiEnvelopeEncoder {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(PkcsPkiEnvelopeEncoder.class);
    private final X509Certificate recipient;
    private final ASN1ObjectIdentifier encAlgId;

    /**
     * Creates a new <tt>PkcsPkiEnvelopeEncoder</tt> for the entity identified
     * by the provided certificate.
     * 
     * @param recipient
     *            the entity for whom the <tt>pkcsPkiEnvelope</tt> is intended.
     */
    @Deprecated
    public PkcsPkiEnvelopeEncoder(final X509Certificate recipient) {
        this(recipient, "DES");
    }

    /**
     * Creates a new <tt>PkcsPkiEnvelopeEncoder</tt> for the entity identified
     * by the provided certificate.
     * 
     * @param recipient
     *            the entity for whom the <tt>pkcsPkiEnvelope</tt> is intended.
     * @param encAlg
     *            the encryption algorithm to use.
     */
    public PkcsPkiEnvelopeEncoder(final X509Certificate recipient,
            final String encAlg) {
        this.recipient = recipient;
        this.encAlgId = getAlgorithmId(encAlg);
    }

    /**
     * Encrypts and envelops the provided messageData.
     * 
     * @param messageData
     *            the message data to encrypt and envelop.
     * @return the enveloped data.
     * @throws MessageEncodingException
     *             if there are any problems encoding the message.
     */
    public CMSEnvelopedData encode(final byte[] messageData)
            throws MessageEncodingException {
        LOGGER.debug("Encoding pkcsPkiEnvelope");
        CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
        CMSTypedData envelopable = new CMSProcessableByteArray(messageData);
        RecipientInfoGenerator recipientGenerator;
        try {
            recipientGenerator = new JceKeyTransRecipientInfoGenerator(
                    recipient);
        } catch (CertificateEncodingException e) {
            throw new MessageEncodingException(e);
        }
        edGenerator.addRecipientInfoGenerator(recipientGenerator);
        LOGGER.debug(
                "Encrypting pkcsPkiEnvelope using key belonging to [dn={}; serial={}]",
                recipient.getSubjectDN(), recipient.getSerialNumber());

        OutputEncryptor encryptor;
        try {
            encryptor = new JceCMSContentEncryptorBuilder(encAlgId).build();
        } catch (CMSException e) {
            throw new MessageEncodingException(e);
        }
        try {
            CMSEnvelopedData pkcsPkiEnvelope = edGenerator.generate(
                    envelopable, encryptor);

            LOGGER.debug("Finished encoding pkcsPkiEnvelope");
            return pkcsPkiEnvelope;
        } catch (CMSException e) {
            throw new MessageEncodingException(e);
        }
    }

    private ASN1ObjectIdentifier getAlgorithmId(String encAlg) {
        if ("DES".equals(encAlg)) {
            return DES_CBC;
        } 
        else if("AES".equals(encAlg) || "AES_128".equals(encAlg)){
            return AES128_CBC;
        }
        else if ("AES_192".equals(encAlg)) {
            return AES192_CBC;
        }
        else if ("AES_256".equals(encAlg)) {
            return AES256_CBC;
        }
        else if ("DESede".equals(encAlg)) {
            return DES_EDE3_CBC;
        }
        else {
            throw new IllegalArgumentException("Unknown algorithm: " + encAlg);
        }
    }
}

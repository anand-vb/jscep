package org.jscep.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.cert.X509CRLHolder;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cms.*;
import org.spongycastle.cms.jcajce.JcaSignerId;
import org.spongycastle.operator.*;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * This class contains utility methods for manipulating SignedData objects.
 */
public final class SignedDataUtils {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(SignedDataUtils.class);

    /**
     * Private constructor to prevent instantiation.
     */
    private SignedDataUtils() {
    }

    /**
     * Checks if the provided signedData was signed by the entity represented by
     * the provided certificate.
     * 
     * @param sd
     *            the signedData to verify.
     * @param signer
     *            the signing entity.
     * @return <code>true</code> if the signedData was signed by the entity,
     *         <code>false</code> otherwise.
     */
    public static boolean isSignedBy(final CMSSignedData sd,
            final X509Certificate signer) {
        SignerInformationStore store = sd.getSignerInfos();
        SignerInformation signerInfo = store.get(new JcaSignerId(signer));
        if (signerInfo == null) {
            return false;
        }
        CMSSignatureAlgorithmNameGenerator sigNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        SignatureAlgorithmIdentifierFinder sigAlgorithmFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        ContentVerifierProvider verifierProvider;
        try {
            verifierProvider = new JcaContentVerifierProviderBuilder()
                    .build(signer);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        DigestCalculatorProvider digestProvider;
        try {
            digestProvider = new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e1) {
            throw new RuntimeException(e1);
        }
        SignerInformationVerifier verifier = new SignerInformationVerifier(
                sigNameGenerator, sigAlgorithmFinder, verifierProvider,
                digestProvider);
        try {
            return signerInfo.verify(verifier);
        } catch (CMSException e) {
            return false;
        }
    }

    /**
     * Converts a Bouncy Castle <tt>signedData</tt> object into a
     * <tt>CertStore</tt>.
     * <p>
     * This method will extract all certificates and CRLs from the
     * <tt>signedData</tt>. It makes <strong>no</strong> attempt to verify the
     * integrity of the <tt>signedData</tt>.
     * 
     * @param signedData
     *            the <tt>signedData</tt> to etract.
     * @return the extracted certificates and CRLs.
     */
    public static CertStore fromSignedData(final CMSSignedData signedData) {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        Store certStore = signedData.getCertificates();
        Store crlStore = signedData.getCRLs();

        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> certs = certStore.getMatches(null);
        @SuppressWarnings("unchecked")
        Collection<X509CRLHolder> crls = crlStore.getMatches(null);

        Collection<Object> certsAndCrls = new ArrayList<Object>();

        for (X509CertificateHolder cert : certs) {
            ByteArrayInputStream byteIn;
            try {
                byteIn = new ByteArrayInputStream(cert.getEncoded());
            } catch (IOException e) {
                LOGGER.error("Error encoding certificate", e);

                continue;
            }
            try {
                certsAndCrls.add(factory.generateCertificate(byteIn));
            } catch (CertificateException e) {
                LOGGER.error("Error generating certificate", e);
            }
        }

        for (X509CRLHolder crl : crls) {
            ByteArrayInputStream byteIn;
            try {
                byteIn = new ByteArrayInputStream(crl.getEncoded());
            } catch (IOException e) {
                LOGGER.error("Error encoding crl", e);

                continue;
            }
            try {
                certsAndCrls.add(factory.generateCRL(byteIn));
            } catch (CRLException e) {
                LOGGER.error("Error generating certificate", e);
            }
        }

        try {
            return CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certsAndCrls));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}

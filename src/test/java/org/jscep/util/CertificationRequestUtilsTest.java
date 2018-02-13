package org.jscep.util;

import org.junit.Test;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class CertificationRequestUtilsTest {
    private PKCS10CertificationRequest getCsr(ASN1Encodable challengePassword)
            throws Exception {

        final X500Name subject = new X500Name("CN=Test");

        final KeyPair keyPair = KeyPairGenerator.getInstance("RSA")
            .genKeyPair();

        final SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo
            .getInstance(keyPair.getPublic().getEncoded());

        final ContentSigner signer = new JcaContentSignerBuilder(
            "SHA1withRSA").build(keyPair.getPrivate());

        final PKCS10CertificationRequestBuilder builder =
            new PKCS10CertificationRequestBuilder(subject, pkInfo);
        if (challengePassword != null) {
            builder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                challengePassword);
        }
        return builder.build(signer);
    }

    @Test
    public void testGetChallengePasswordPrintableString() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(new DERPrintableString(
            "test password"));
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is("test password"));
    }

    @Test
    public void testGetChallengePasswordUtf8String() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(new DERUTF8String(
            "test_password"));
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is("test_password"));
    }

    @Test
    public void testGetChallengePasswordNull() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(null);
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is(nullValue()));
    }
}

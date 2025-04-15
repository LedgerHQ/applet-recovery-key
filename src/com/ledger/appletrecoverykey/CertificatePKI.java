package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.APDU_HEADER_SIZE;
import static com.ledger.appletrecoverykey.Constants.CERTIFICATE_SIGNATURE_TAG;
import static com.ledger.appletrecoverykey.Constants.SW_SECURITY_STATUS;
import static com.ledger.appletrecoverykey.Constants.SW_WRONG_LENGTH;
import static com.ledger.appletrecoverykey.Utils.parseTLVGetOffset;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class CertificatePKI {
    // Certificate length
    private short rawCertificateLength;
    // Certificate with TLV fields
    private byte[] rawCertificate = null;
    // Issuer verification key
    private ECPublicKey issuerPublicKey;
    // Signature instance for certificate signature verification
    Signature signature;
    Curve curve;
    private static final short MAX_CERT_LEN = 256;

    public CertificatePKI() {
        this.rawCertificateLength = 0;
        this.rawCertificate = new byte[MAX_CERT_LEN];
        this.issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) KeyBuilder.LENGTH_EC_FP_256, false);
        this.signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        this.curve = new Secp256k1();
    }

    /**
     * Writes the certificate value into non-volatile memory.
     * 
     * @param[in] certificate Certificate buffer
     * @param[in] offset Offset of the certificate value
     * @param[in] certificateLength Length of the certificate
     */
    protected void setCertificate(byte[] certificate, short offset, short certificateLength) {
        if (certificateLength > MAX_CERT_LEN) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        Util.arrayCopy(certificate, offset, this.rawCertificate, (short) 0, certificateLength);
        this.rawCertificateLength = certificateLength;

    }

    /**
     * Initializes the Issuer public key used to verify the certificate signature
     * 
     * @param[in] publicKey Public key buffer
     * @param[in] offset Offset of the public key value
     * @param[in] publicKeyLength Public key length
     */
    protected void setIssuerPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        // This method should be called once during applet installation
        // issuerPublicKey is kept after the upgrade
        this.curve.setCurveParameters(this.issuerPublicKey);
        this.issuerPublicKey.setW(publicKey, offset, (short) publicKeyLength);
    }

    /**
     * Gets the certificate
     * 
     * @param[out] outCertificate Buffer to return the certificate
     * @param[in] offset Offset for the certificate value
     * @return Certificate length
     */
    protected short getCertificate(byte[] outCertificate, short offset) {
        Util.arrayCopy(this.rawCertificate, (short) 0, outCertificate, offset, this.rawCertificateLength);
        return this.rawCertificateLength;
    }

    /**
     * Gets the Issuer public key
     * 
     * @param[out] outPublicKey Buffer to return the public key
     * @param[in] offset Offset for the public key value
     * @return Public key length
     */
    protected short getIssuerPublicKey(byte[] outPublicKey, short offset) {
        return this.issuerPublicKey.getW(outPublicKey, offset);
    }

    /**
     * Verifies the Issuer signature against the certificate data
     * 
     * @param[in] certificate Certificate buffer
     * @param[in] offset Offset of the certificate value
     * @param[in] length Length of the certificate buffer
     * @return True if the signature is verified False otherwise
     */
    protected boolean verifySignature(byte[] certificate, short offset, short length) {
        // parse certificate to get the signature length and the signature value (tag =
        // 0x15)
        short signatureOffset = parseTLVGetOffset(CERTIFICATE_SIGNATURE_TAG, certificate, offset, length);
        short signatureLength = (short) (certificate[signatureOffset] & 0xFF);
        signatureOffset++;

        this.signature.init(this.issuerPublicKey, Signature.MODE_VERIFY);

        short certificateLength = (short) (length - APDU_HEADER_SIZE);
        boolean isVerified = this.signature.verify(certificate, offset, (short) (certificateLength - signatureLength - 2), certificate,
                signatureOffset, signatureLength);

        if (!isVerified) {
            ISOException.throwIt(SW_SECURITY_STATUS);
        }

        setCertificate(certificate, offset, certificateLength);
        return isVerified;
    }

    /**
     * Verifies whether a certificate is set
     * 
     * @return True if a certificate has been set False otherwise
     */
    protected boolean isCertificateSet() {
        return (this.rawCertificateLength != 0);
    }

    /**
     * Saves Certificate instance during upgrade
     * 
     * @param[in] certificate Certificate instance to save
     * @return Upgrade Element
     */
    static Element save(CertificatePKI certificate) {
        if (certificate == null) {
            return null;
        }
        short primitiveCount = 2; // rawCertificateLength,
        short objectCount = 2; // rawCertificate, issuerPublicKey
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, primitiveCount, objectCount).write(certificate.rawCertificateLength)
                .write(certificate.rawCertificate).write(certificate.issuerPublicKey);
    }

    /**
     * Restores an upgrade Element into a Certificate instance
     * 
     * @param[in] element Upgrade Element to restore
     * @return Certificate instance
     */
    static CertificatePKI restore(Element element) {
        if (element == null) {
            return null;
        }
        CertificatePKI cert = new CertificatePKI();
        cert.rawCertificateLength = element.readShort();
        cert.rawCertificate = (byte[]) element.readObject();
        cert.issuerPublicKey = (ECPublicKey) element.readObject();
        return cert;
    }
}

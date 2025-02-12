package com.ledger.appletcharon;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.framework.Util;
import javacard.framework.ISOException;
import static com.ledger.appletcharon.Constants.CERTIFICATE_PUBLIC_KEY_TAG;
import static com.ledger.appletcharon.Constants.CERTIFICATE_SIGNATURE_TAG;
import static com.ledger.appletcharon.Constants.SW_REFERENCE_DATA_NOT_FOUND;
import static com.ledger.appletcharon.Constants.SW_WRONG_LENGTH;
import static com.ledger.appletcharon.Constants.SW_SECURITY_STATUS;;

public class CertificatePKI {
    // Certificate length
    private short rawCertificateLength;
    // Certificate with TLV fields
    private byte[] rawCertificate = null;
    // Issuer verification key
    private ECPublicKey issuerPublicKey;
    // Signature instance for certificate signature verification
    Signature signature;
    private static final short MAX_CERT_LEN = 256;

    public CertificatePKI() {
        this.rawCertificateLength = 0;
        this.rawCertificate = new byte[MAX_CERT_LEN];
        this.issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) KeyBuilder.LENGTH_EC_FP_256, false);
        this.signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    /**
     * Parses the TLV-encoded certificate given a tag and copies the
     * data field corresponding to the tag.
     * @param[in]  tag       Tag of the data to copy
     * @param[in]  tlvData   TLV data buffer
     * @param[in]  offset    Offset of the TLV data
     * @param[in]  length    Length of the TLV data
     * @param[out] outValue  Buffer to store the tag data
     * @param[in]  outOffset Offset of the buffer
     * @return
     */
    private short parseTLV(byte tag, byte[] tlvData, short offset, short length, byte[] outValue, short outOffset) {
        short end = (short) (offset + length);
        boolean isTagFound = false;
        short len = 0;

        while (!isTagFound && (offset < end)) {
            // Read the tag
            byte currentTag = (byte) (tlvData[offset] & 0xFF);
            offset++;

            // Read the length
            len = (short) (tlvData[offset] & 0xFF);
            offset++;

            // Copy the value
            if (currentTag == tag) {
                Util.arrayCopy(tlvData, offset, outValue, outOffset, len);
                isTagFound = true;
            }
            offset += len;
        }

        if (!isTagFound) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        // Return the length
        return len;
    }

    /**
     * Parses the TLV-encoded certificate given a tag and returns the
     * offset of the data length.
     * @param[in]  tag       Tag of the data
     * @param[in]  tlvData   TLV data buffer
     * @param[in]  offset    Offset of the TLV data
     * @param[in]  length    Length of the TLV data
     * @return Offset of the data length
     */
    protected short parseTLVGetOffset(byte tag, byte[] tlvData, short offset, short length) {
        short end = (short) (offset + length);
        boolean isTagFound = false;
        short outOffset = 0;
        short len = 0;

        while (!isTagFound && (offset < end)) {
            // Read the tag
            byte currentTag = (byte) (tlvData[offset] & 0xFF);
            offset++;

            if (currentTag == tag) {
                isTagFound = true;
                // Offset corresponding to the length
                outOffset = offset;
            }

            // Read the length
            len = (short) (tlvData[offset] & 0xFF);
            offset++;

            offset += len;
        }

        if (!isTagFound) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        // Return the offset
        return outOffset;
    }

    /**
     * Writes the certificate value into non-volatile memory.
     * @param[in] certificate        Certificate buffer
     * @param[in] offset             Offset of the certificate value
     * @param[in] certificateLength  Length of the certificate
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
     * @param[in] publicKey       Public key buffer
     * @param[in] offset          Offset of the public key value
     * @param[in] publicKeyLength Public key length
     */
    protected void setIssuerPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        // This method should be called once during applet installation
        // issuerPublicKey is kept after the upgrade
        Curve curve = new Secp256k1();
        curve.setCurveParameters(this.issuerPublicKey);
        this.issuerPublicKey.setW(publicKey, offset, (short) publicKeyLength);
    }

    /**
     * Gets the certificate
     * @param[out] outCertificate Buffer to return the certificate
     * @param[in]  offset         Offset for the certificate value
     * @return Certificate length
     */
    protected short getCertificate(byte[] outCertificate, short offset) {
        Util.arrayCopy(this.rawCertificate, (short) 0, outCertificate, offset, this.rawCertificateLength);
        return this.rawCertificateLength;
    }

    /**
     * Gets the Issuer public key
     * @param[out] outPublicKey Buffer to return the public key
     * @param[in]  offset       Offset for the public key value
     * @return Public key length
     */
    protected short getIssuerPublicKey(byte[] outPublicKey, short offset) {
        return this.issuerPublicKey.getW(outPublicKey, offset);
    }

    /**
     * Verifies the Issuer signature against the certificate data
     * @param[in] certificate Certificate buffer
     * @param[in] offset      Offset of the certificate value
     * @param[in] length      Length of the certificate buffer
     * @return True if the signature is verified
     * False otherwise
     */
    protected boolean verifySignature(byte[] certificate, short offset, short length) {
        // certificate = certificateLength || certificateValue
        // parse certificate to get the signature length and the signature value (tag = 0x15)
        short signatureOffset = parseTLVGetOffset(CERTIFICATE_SIGNATURE_TAG, certificate, (short) (offset + 1), length);
        short signatureLength = (short) (certificate[signatureOffset] & 0xFF);
        signatureOffset++;

        this.signature.init(this.issuerPublicKey, Signature.MODE_VERIFY);

        short certificateLength = (short) (certificate[offset] & 0xFF);
        boolean isVerified = this.signature.verify(certificate, (short) (offset + 1), (short) (certificateLength - signatureLength - 2), certificate, signatureOffset, signatureLength);

        if (!isVerified) {
            ISOException.throwIt(SW_SECURITY_STATUS);
        }

        setCertificate(certificate, (short) (offset + 1), certificateLength);
        return isVerified;
    }

    /**
     * Verifies whether a certificate is set
     * @return True if a certificate has been set
     * False otherwise
     */
    protected boolean isCertificateSet() {
        return (this.rawCertificateLength != 0);
    }

    /**
     * Saves Certificate instance during upgrade
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

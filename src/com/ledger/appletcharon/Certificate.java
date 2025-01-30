/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.SN_LENGTH;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class Certificate {
    // Certificate role
    private byte[] role;
    // Curve associated to publicKey and issuerPublicKey
    private Curve curve;
    // Serial number associated to issuerPublicKey
    private byte[] batchSerial = null;
    // Card serial number
    protected byte[] serialNumber = null;
    // Card serial number length
    private short serialNumberLength;
    // Card public key
    protected byte[] publicKey = null;
    // Card public key length
    private short publicKeyLength;
    // Issuer public key
    protected byte[] issuerPublicKey = null;
    // Issuer public key length
    private short issuerPublicKeyLength;
    // Issuer signature
    protected byte[] signature = null;
    // Issuer signature length
    private short signatureLength;

    // Batch serial number length
    protected static final short BATCH_SERIAL_LEN = 4;
    private static final short MAX_PUBLIC_KEY_LEN = 65;
    private static final short MAX_SIGNATURE_LEN = 72; // DER encoded signature length

    public Certificate(byte role) {
        this.role = new byte[1];
        this.role[0] = role;
        this.serialNumber = new byte[SN_LENGTH];
        this.serialNumberLength = 0;
        this.publicKey = new byte[MAX_PUBLIC_KEY_LEN];
        this.publicKeyLength = 0;
        this.issuerPublicKey = new byte[MAX_PUBLIC_KEY_LEN];
        this.issuerPublicKeyLength = 0;
        this.signature = new byte[MAX_SIGNATURE_LEN];
        this.signatureLength = 0;
        this.batchSerial = new byte[BATCH_SERIAL_LEN];
    }

    /**
     * Keeps the Card certificate public key into internal array.
     * This is convenient for the certificate signature verification and
     * for the getCertificate method.
     * @param[in] publicKey       Public key buffer
     * @param[in] offset          Offset of the public key value
     * @param[in] publicKeyLength Public key length
     */
    protected void setPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
        Util.arrayFill(this.publicKey, (short) 0, (short) this.publicKey.length, (byte) 0);
        Util.arrayCopy(publicKey, offset, this.publicKey, (short) 0, publicKeyLength);
    }

    /**
     * Keeps the Issuer public key. This public key is used to verify the certificate
     * signature.
     * @param[in] publicKey       Public key buffer
     * @param[in] offset          Offset of the public key value
     * @param[in] publicKeyLength Public key length
     */
    protected void setIssuerPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        this.issuerPublicKeyLength = publicKeyLength;
        Util.arrayFill(this.issuerPublicKey, (short) 0, (short) this.issuerPublicKey.length, (byte) 0);
        Util.arrayCopy(publicKey, offset, this.issuerPublicKey, (short) 0, publicKeyLength);
    }

    /**
     * Keeps the Issuer signature as certificate signature.
     * The signature has been computed over {role || serialNumber || publicKey}
     * @param[in] signature       Signature buffer
     * @param[in] offset          Offset of the signature value
     * @param[in] signatureLength Signature length
     */
    protected void setSignature(byte[] signature, short offset, short signatureLength) {
        this.signatureLength = signatureLength;
        Util.arrayFill(this.signature, (short) 0, (short) this.signature.length, (byte) 0);
        Util.arrayCopy(signature, offset, this.signature, (short) 0, signatureLength);
    }

    /**
     * Keeps the batch serial number which identifies the Issuer public key.
     * @param[in] batchSerial Batch serial number buffer
     * @param[in] offset      Offset to the batch serial number value
     */
    protected void setBatchSerial(byte[] batchSerial, short offset) {
        Util.arrayCopy(batchSerial, offset, this.batchSerial, (short) 0, BATCH_SERIAL_LEN);
    }

    /**
     * Keeps the card serial number.
     * This is convenient for the certificate signature verification and
     * for the getCertificate method.
     * @param[in] serialNumber Card serial number buffer
     * @param[in] offset       Offset of the card serial number value
     * @param[in] serialNumberLength Card serial number length
     */
    protected void setSerialNumber(byte[] serialNumber, short offset, short serialNumberLength) {
        this.serialNumberLength = serialNumberLength;
        Util.arrayFill(this.serialNumber, (short) 0, (short) this.serialNumber.length, (byte) 0);
        Util.arrayCopy(serialNumber, offset, this.serialNumber, (short) 0, serialNumberLength);
    }

    /**
     * Gets the Issuer public key. This Issuer public key will be used to verify
     * the certificate received by the card.
     * @param[out] outPublicKey      Buffer where to store the public key
     * @param[in] offset             Offset of the public key value
     * @return issuerPublicKeyLength Length of the Issuer public key
     */
    protected short getIssuerPublicKey(byte[] outPublicKey, short offset) {
        Util.arrayCopy(issuerPublicKey, (short) 0, outPublicKey, offset, issuerPublicKeyLength);
        return issuerPublicKeyLength;
    }

    /**
     * Sets the curve on which the public keys have been defined.
     * It is assumed that both Issuer public key and card public key
     * correspond to this curve.
     * @param curve
     */
    protected void setCurve(Curve curve) {
        this.curve = curve;
    }

    /**
     * Gets the card certificate.
     * The certificate consists of
     * {serialNumberLength || serialNumber || publicKeyLength || publicKey || signatureLength || signature}
     * @param[out] outCertificate Certificate buffer
     * @param[in] offset          Offset of the certificate
     * @return Length of the certificate
     */
    protected short getCertificate(byte[] outCertificate, short offset) {
        short dataOffset = offset;
        outCertificate[dataOffset] = (byte) serialNumberLength;
        dataOffset += (short) 1;
        Util.arrayCopy(serialNumber, (short) 0, outCertificate, dataOffset, serialNumberLength);
        dataOffset = (short) (serialNumberLength + 1);
        outCertificate[dataOffset] = (byte) publicKeyLength;
        dataOffset += (short) 1;
        Util.arrayCopy(publicKey, (short) 0, outCertificate, dataOffset, publicKeyLength);
        dataOffset += publicKeyLength;
        outCertificate[dataOffset] = (byte) signatureLength;
        dataOffset += (short) 1;
        Util.arrayCopy(signature, (short) 0, outCertificate, dataOffset, signatureLength);
        dataOffset += signatureLength;
        return (short) (dataOffset - offset);
    }

    /**
     * Erases the Certificate content.
     */
    protected void eraseAll() {
        role[0] = (byte) 0;
        curve.eraseCurve();
        Util.arrayFill(batchSerial, (short) 0, (short) BATCH_SERIAL_LEN, (byte) 0);
        Util.arrayFill(serialNumber, (short) 0, serialNumberLength, (byte) 0);
        Util.arrayFill(publicKey, (short) 0, publicKeyLength, (byte) 0);
        Util.arrayFill(issuerPublicKey, (short) 0, issuerPublicKeyLength, (byte) 0);
        Util.arrayFill(signature, (short) 0, signatureLength, (byte) 0);
        publicKeyLength = 0;
        issuerPublicKeyLength = 0;
        signatureLength = 0;
    }

    /**
     * Verifies the certificate signature.
     * @return true  Signature is verified
     *         false Signature is not verified
     */
    protected boolean verifySignature() {
        ECPublicKey issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) curve.getCurveLength(),
                false);
        curve.setCurveParameters(issuerPublicKey);
        issuerPublicKey.setW(this.issuerPublicKey, (short) 0, (short) issuerPublicKeyLength);

        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(issuerPublicKey, Signature.MODE_VERIFY);
        signature.update(role, (short) 0, (short) 1);
        signature.update(serialNumber, (short) 0, serialNumberLength);

        boolean isVerified = signature.verify(publicKey, (short) 0, publicKeyLength, this.signature, (short) 0, signatureLength);

        if (isVerified == false) {
            // TODO: implement fatal error, this should never happen (?)
            eraseAll();
        }
        return isVerified;
    }

    protected boolean isCertificateSet() {
        return (publicKeyLength != 0 && issuerPublicKeyLength != 0 && signatureLength != 0);
    }

    static Element save(Certificate certificate) {
        if (certificate == null || certificate.signature == null) {
            return null;
        }
        short primitiveCount = 1 + 2 * 3; // role, publicKeyLength, signatureLength, issuerPublicKeyLength,
        short objectCount = 4; // serialNumber, publicKey, signature, issuerPublicKey
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, primitiveCount, objectCount).write(certificate.role[0])
                .write(certificate.publicKeyLength).write(certificate.signatureLength).write(certificate.issuerPublicKeyLength)
                .write(certificate.serialNumber).write(certificate.publicKey).write(certificate.signature)
                .write(certificate.issuerPublicKey);
    }

    static Certificate restore(Element element) {
        if (element == null) {
            return null;
        }
        Certificate cert = new Certificate(element.readByte());
        cert.publicKeyLength = element.readShort();
        cert.signatureLength = element.readShort();
        cert.issuerPublicKeyLength = element.readShort();
        cert.serialNumber = (byte[]) element.readObject();
        cert.serialNumberLength = (short) cert.serialNumber.length;
        cert.publicKey = (byte[]) element.readObject();
        cert.signature = (byte[]) element.readObject();
        cert.issuerPublicKey = (byte[]) element.readObject();
        return cert;
    }
}

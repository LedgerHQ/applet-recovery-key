/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;

public class CryptoUtil {
    // Curve associated with the key pair
    private Curve curve;
    // Private key used for signature
    private ECPrivateKey signingKey;
    private ECPublicKey verificationKey;

    /* Constants */
    // SECP256K1 identifier
    protected static final byte SECP256K1 = (byte) 0x21;
    // Private key length over SECP256K1
    protected static final byte SECP256K1_PRIVATE_KEY_LEN = (byte) 32;

    /**
     * Initializes a curve for key generation, signature and, verification
     * 
     * @param[in] curveId Curve identifier
     */
    protected void initCurve(byte curveId) {
        switch (curveId) {
        case SECP256K1:
            curve = new Secp256k1();
            break;
        // Add other curves if needed
        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * Gets the current curve.
     * 
     * @return Curve object
     */
    protected Curve getCurve() {
        return this.curve;
    }

    /**
     * Generates an elliptic curve key pair over the initialized curve.
     * 
     * @param[in] buffer Buffer for temporary storage
     * @param[in] offset Buffer offset
     * @param[out] privateKey PrivateKey object. It must be instanciated.
     * @param[out] publicKey PublicKey object. It must be instanciated.
     */
    protected void generateKeyPair(byte[] buffer, short offset, ECPrivateKey privateKey, ECPublicKey publicKey) {
        try {
            curve.setCurveParameters(privateKey);
            RandomData randomData = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
            randomData.nextBytes(buffer, offset, (short) (curve.getCurveLength() / 8));
            privateKey.setS(buffer, offset, (short) (curve.getCurveLength() / 8));
            curve.setCurveParameters(publicKey);
            curve.multiplyGenerator(privateKey, publicKey);
        } catch (Exception e) {
            Util.arrayFill(buffer, offset, (short) (curve.getCurveLength() / 8), (byte) 0);
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Instanciates a signing key in a transient key object.
     * 
     * @param[in] privateKeyBuffer Private key buffer
     * @param[in] offset Offset of the private key value
     * @param[in] length Private key length
     */
    protected void setSigningKey(byte[] privateKeyBuffer, short offset, short length) {
        signingKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                curve.getCurveLength(), false);
        curve.setCurveParameters(signingKey);
        signingKey.setS(privateKeyBuffer, offset, length);
    }

    protected void setVerificationKey(byte[] publicKeyBuffer, short offset, short length) {
        verificationKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, curve.getCurveLength(),
                false);
        curve.setCurveParameters(verificationKey);
        verificationKey.setW(publicKeyBuffer, offset, length);
    }

    /**
     * Computes a signature using an initialized signing key.
     * 
     * @param[in] dataBuffer Data buffer
     * @param[in] offset Offset of the data
     * @param[in] dataLength Data length
     * @param[out] signatureBuffer Signature buffer
     * @param[in] signatureOffset Offset of the signature
     * @return Signature length
     */
    protected short computeSignature(byte[] dataBuffer, short offset, short dataLength, byte[] signatureBuffer,
            short signatureOffset) {
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(signingKey, Signature.MODE_SIGN);
        return signature.sign(dataBuffer, offset, dataLength, signatureBuffer, signatureOffset);
    }

    protected short computeSignatureWithKey(byte[] dataBuffer, short offset, short dataLength, byte[] signatureBuffer,
            short signatureOffset, ECPrivateKey signingKey) {
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(signingKey, Signature.MODE_SIGN);
        return signature.sign(dataBuffer, offset, dataLength, signatureBuffer, signatureOffset);
    }

    protected boolean verifySignature(byte[] dataBuffer, short offset, short dataLength, byte[] signatureBuffer,
            short signatureOffset, short signatureLength) {
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(verificationKey, Signature.MODE_VERIFY);
        return signature.verify(dataBuffer, offset, dataLength, signatureBuffer, signatureOffset, signatureLength);
    }
}

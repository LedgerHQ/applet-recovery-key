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
    private Curve curve;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;
    private ECPrivateKey signingKey;

    // static fields
    protected static final byte SECP256K1 = (byte) 0x21;
    protected static final byte SECP256K1_PRIVATE_KEY_LEN = (byte) 32;

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

    protected Curve getCurve() {
        return this.curve;
    }

    protected void generateKeyPair(byte[] buffer, short offset) {
        try {
            privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, curve.getCurveLength(), false);
            curve.setCurveParameters(privateKey);
            RandomData randomData = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
            randomData.nextBytes(buffer, offset, (short) (curve.getCurveLength()/8));
            privateKey.setS(buffer, offset, (short) (curve.getCurveLength()/8));
            publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, curve.getCurveLength(), false);
            curve.setCurveParameters(publicKey);
            curve.multiplyGenerator(privateKey, publicKey);
        } catch(Exception e) {
            Util.arrayFill(buffer, offset, (short) (curve.getCurveLength()/8), (byte) 0);
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        } 
    }

    protected short getPublicKey(byte[] publicKeyBuffer, short offset) {
        return publicKey.getW(publicKeyBuffer, offset);
    }

    protected void setSigningKey(byte[] privateKeyBuffer, short offset, short length) {
        signingKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, curve.getCurveLength(), false);
        curve.setCurveParameters(signingKey);
        signingKey.setS(privateKeyBuffer, offset, length);
    }

    protected short computeSignature(byte[] dataBuffer, short offset, short dataLength, byte[] signatureBuffer, short signatureOffset) {
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(signingKey, Signature.MODE_SIGN);

        return signature.sign(dataBuffer, offset, dataLength, signatureBuffer, signatureOffset);
    }
}

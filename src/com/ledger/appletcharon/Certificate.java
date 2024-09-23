/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.ledger.appletcharon;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class Certificate {
    private byte[] role;
    private Curve curve;
    private byte[] batchSerial = null;
    private byte[] publicKey = null;
    private short publicKeyLength;
    private byte[] signature = null;
    private short signatureLength;

    protected static final short BATCH_SERIAL_LEN = 4;

    public Certificate(byte role) {
        this.role = new byte[1];
        this.role[0] = role;
    }

    protected void setPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
        this.publicKey = new byte[publicKeyLength];
        Util.arrayCopy(publicKey, offset, this.publicKey, (short) 0, publicKeyLength);
    }

    protected void setSignature(byte[] signature, short offset, short signatureLength) {
        this.signatureLength = signatureLength;
        this.signature = new byte[signatureLength];
        Util.arrayCopy(signature, offset, this.signature, (short) 0, signatureLength); 	
    }

    protected void setBatchSerial(byte[] batchSerial, short offset) {
        this.batchSerial = new byte[BATCH_SERIAL_LEN];
        Util.arrayCopy(batchSerial, offset, this.batchSerial, (short) 0, BATCH_SERIAL_LEN);
    }

    protected short getPublicKey(byte[] outPublicKey) {
    	Util.arrayCopy(outPublicKey, (short) 0, publicKey, (short) 0, publicKeyLength);
    	return publicKeyLength;
    }
    
    protected short getSignature(byte[] outSignature) {
        Util.arrayCopy(outSignature, (short) 0, signature, (short) 0, signatureLength);
        return signatureLength;
    }

    protected void getBatchSerial(byte[] outSerial) {
        Util.arrayCopy(outSerial, (short) 0, batchSerial, (short) 0, (short) 4);
    }

    protected void setCurve(Curve curve) {
        this.curve = curve;
    }

    protected void eraseAll() {
        role[0] = (byte) 0;
        curve.eraseCurve();
        Util.arrayFill(batchSerial, (short) 0, (short) BATCH_SERIAL_LEN, (byte) 0);
        Util.arrayFill(publicKey, (short) 0, publicKeyLength, (byte) 0);
        Util.arrayFill(signature, (short) 0, signatureLength, (byte) 0);
        publicKeyLength = 0;
        signatureLength = 0;
    }

    protected boolean verifySignature(byte[] signedData, short offset, short signedDataLength) {
        ECPublicKey issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) curve.getCurveLength(), false);
        curve.setCurveParameters(issuerPublicKey);
        issuerPublicKey.setW(publicKey, (short) 0, (short) publicKeyLength);

        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(issuerPublicKey, Signature.MODE_VERIFY);
        signature.update(role, (short) 0, (short) 1);

        boolean isVerified = signature.verify(signedData, offset, signedDataLength, this.signature, (short) 0, signatureLength);

        if (isVerified == false) {
            eraseAll();
        }
        return isVerified;
    }
}

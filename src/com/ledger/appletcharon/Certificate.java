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
    private byte[] mcuSerial = null;
    private short mcuSerialLength;

    protected static final short BATCH_SERIAL_LEN = 4;
    private static final byte ISSUER_PUBLIC_KEY[] = {
            (byte) 0x04, (byte) 0x81, (byte) 0xbc, (byte) 0x1f,
            (byte) 0x94, (byte) 0x86, (byte) 0x56, (byte) 0x4d,
            (byte) 0x3d, (byte) 0x57, (byte) 0xa3, (byte) 0x05,
            (byte) 0xe8, (byte) 0xf9, (byte) 0x06, (byte) 0x7d,
            (byte) 0xf2, (byte) 0xa7, (byte) 0xe1, (byte) 0xf0,
            (byte) 0x07, (byte) 0xd4, (byte) 0xaf, (byte) 0x4f,
            (byte) 0xed, (byte) 0x08, (byte) 0x5a, (byte) 0xca,
            (byte) 0x13, (byte) 0x9c, (byte) 0x6b, (byte) 0x9c,
            (byte) 0x7a, (byte) 0x8e, (byte) 0x3f, (byte) 0x35,
            (byte) 0xe4, (byte) 0xd7, (byte) 0xfb, (byte) 0x27,
            (byte) 0xa5, (byte) 0x6a, (byte) 0x3f, (byte) 0x35,
            (byte) 0xd3, (byte) 0x4c, (byte) 0x8c, (byte) 0x2b,
            (byte) 0x27, (byte) 0xcd, (byte) 0x1d, (byte) 0x26,
            (byte) 0x6d, (byte) 0x52, (byte) 0x94, (byte) 0xdf,
            (byte) 0x13, (byte) 0x1b, (byte) 0xf3, (byte) 0xc1,
            (byte) 0xcb, (byte) 0xc3, (byte) 0x9f, (byte) 0x5a,
            (byte) 0x91};

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

    protected void setMcuSerial(byte[] mcuSerial, short offset, short mcuSerialLength) {
        this.mcuSerialLength = mcuSerialLength;
        this.mcuSerial = new byte[mcuSerialLength];
        Util.arrayCopy(mcuSerial, offset, this.mcuSerial, (short) 0, mcuSerialLength);
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

    protected void getMcuSerial(byte[] outMcuSerial) {
        Util.arrayCopy(outMcuSerial, (short) 0, mcuSerial, (short) 0, mcuSerialLength);
    }

    protected void setCurve(Curve curve) {
        this.curve = curve;
    }

    protected void eraseAll() {
        role[0] = (byte) 0;
        // TODO: reset curve
        Util.arrayFill(batchSerial, (short) 0, (short) BATCH_SERIAL_LEN, (byte) 0);
        Util.arrayFill(publicKey, (short) 0, publicKeyLength, (byte) 0);
        Util.arrayFill(signature, (short) 0, signatureLength, (byte) 0);
        Util.arrayFill(mcuSerial, (short) 0, mcuSerialLength, (byte) 0);
        publicKeyLength = 0;
        signatureLength = 0;
        mcuSerialLength = 0;
    }

    protected boolean verifySignature(byte[] serialNumber, short serialNumberLength) {
        ECPublicKey issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) curve.getCurveLength(), false);
        curve.setCurveParameters(issuerPublicKey);
        issuerPublicKey.setW(ISSUER_PUBLIC_KEY, (short) 0, (short) ISSUER_PUBLIC_KEY.length);

        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(issuerPublicKey, Signature.MODE_VERIFY);
        signature.update(role, (short) 0, (short) 1);
        signature.update(serialNumber, (short) 0, (short) serialNumberLength);

        boolean isVerified = signature.verify(publicKey, (short) 0, publicKeyLength, this.signature, (short) 0, signatureLength);

        if (isVerified == false) {
            eraseAll();
        }
        return isVerified;
    }
}

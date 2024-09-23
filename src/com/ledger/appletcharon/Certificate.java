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
    private byte[] serialNumber = null;
    private short serialNumberLength;
    private byte[] publicKey = null;
    private short publicKeyLength;
    private byte[] issuerPublicKey = null;
    private short issuerPublicKeyLength;
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

    protected void setIssuerPublicKey(byte[] publicKey, short offset, short publicKeyLength) {
        this.issuerPublicKeyLength = publicKeyLength;
        this.issuerPublicKey = new byte[publicKeyLength];
        Util.arrayCopy(publicKey, offset, this.issuerPublicKey, (short) 0, publicKeyLength);
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

    protected void setSerialNumber(byte[] serialNumber, short offset, short serialNumberLength) {
        this.serialNumber = new byte[serialNumberLength];
        this.serialNumberLength = serialNumberLength;
        Util.arrayCopy(serialNumber, offset, this.serialNumber, (short) 0, serialNumberLength);
    }

    protected short getIssuerPublicKey(byte[] outPublicKey, short offset) {
        Util.arrayCopy(issuerPublicKey, (short) 0, outPublicKey, offset, issuerPublicKeyLength);
        return issuerPublicKeyLength;
    }

    protected void setCurve(Curve curve) {
        this.curve = curve;
    }

    protected void getCertificate(byte[] outCertificate, short offset) {
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
    }

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

    protected boolean verifySignature() {
        ECPublicKey issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) curve.getCurveLength(), false);
        curve.setCurveParameters(issuerPublicKey);
        issuerPublicKey.setW(this.issuerPublicKey, (short) 0, (short) issuerPublicKeyLength);

        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(issuerPublicKey, Signature.MODE_VERIFY);
        signature.update(role, (short) 0, (short) 1);
        signature.update(serialNumber, (short) 0, serialNumberLength);

        boolean isVerified = signature.verify(publicKey, (short) 0, publicKeyLength, this.signature, (short) 0, signatureLength);

        if (isVerified == false) {
            eraseAll();
        }
        return isVerified;
    }
}

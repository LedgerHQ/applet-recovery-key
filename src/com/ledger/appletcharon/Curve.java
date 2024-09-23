/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.ledger.appletcharon;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;

public class Curve {
    private static KeyAgreement keyGen;
    private short curveLength;
    private byte[] FP = null;
    private byte[] A = null;
    private byte[] B = null;
    private byte[] G = null;
    private byte[] R = null;
    private byte K;
    // SECP384R1 point length including the prefix
    // Assuming that SECP384R1 is the biggest curve that will be used
    private static final short CURVE_MAX_POINT_LEN = 97;
    private byte ramBuffer[] = null;

    public Curve(short curveLength, byte[] FP, byte[] A, byte[] B, byte[] G, byte[] R, byte K) {
        this.curveLength = curveLength;
        this.K = K;
        this.FP = new byte[(short)(curveLength/8)];
        Util.arrayCopy(FP, (short) 0, this.FP, (short) 0, (short)FP.length);
        this.A = new byte[(short)(curveLength/8)];
        Util.arrayCopy(A, (short) 0, this.A, (short) 0, (short)A.length);
        this.B = new byte[(short)(curveLength/8)];
        Util.arrayCopy(B, (short) 0, this.B, (short) 0, (short)B.length);
        this.G = new byte[(short)((curveLength/8) * 2 + 1)];
        Util.arrayCopy(G, (short) 0, this.G, (short) 0, (short)G.length);
        this.R = new byte[(short)(curveLength/8)];
        Util.arrayCopy(R, (short) 0, this.R, (short) 0, (short)R.length);
        if (ramBuffer == null) {
            ramBuffer = JCSystem.makeTransientByteArray((short) (CURVE_MAX_POINT_LEN * 2), JCSystem.CLEAR_ON_DESELECT);
        }
}

    protected short getCurveLength() {
        return curveLength;
    }

    protected boolean setCurveParameters(ECKey key) {
        try {
            key.setA(A, (short) 0, (short) A.length);
            key.setB(B, (short) 0, (short) B.length);
            key.setFieldFP(FP, (short) 0, (short) FP.length);
            key.setG(G, (short) 0, (short) G.length);
            key.setR(R, (short) 0, (short) R.length);
            key.setK(K);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    protected void multiplyGenerator(ECPrivateKey scalar, ECPublicKey result) {
        // TODO: check that keys are initialized
        keyGen = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        keyGen.init(scalar);
        short pointLength = (short)((scalar.getSize() / 8) * 2 + 1);
        // Use ramBuffer to store the generator point and the result point
        short length = scalar.getG(ramBuffer, (short) 0);
        keyGen.generateSecret(ramBuffer, (short) 0, length, ramBuffer, pointLength);
        result.setW(ramBuffer, pointLength, length);	
    }

    protected void multiply(ECPrivateKey scalar, ECPublicKey inPoint, ECPublicKey outPoint) {
        // TODO: check that keys are initialized
        keyGen = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        keyGen.init(scalar);
        short pointLength = (short)((scalar.getSize() / 8) * 2 + 1);
        // Use ramBuffer to store the input point and the output point
        short length = inPoint.getW(ramBuffer, (short) 0);
        keyGen.generateSecret(ramBuffer, (short) 0, length, ramBuffer, pointLength);
        outPoint.setW(ramBuffer, pointLength, length);
    }

    protected void eraseCurve() {
        this.curveLength = 0;
        this.K = 0;
        Util.arrayFill(FP, (short) 0, (short)FP.length, (byte) 0);
        Util.arrayFill(A, (short) 0, (short)A.length, (byte) 0);
        Util.arrayFill(B, (short) 0, (short)B.length, (byte) 0);
        Util.arrayFill(G, (short) 0, (short)G.length, (byte) 0);
        Util.arrayFill(R, (short) 0, (short)R.length, (byte) 0);
    }
}

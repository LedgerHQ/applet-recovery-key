/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.ledger.appletcharon;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;

public class Curve {
    // KeyAgreement object for ECDH
    private static KeyAgreement keyGen;
    // Curve length
    private short curveLength;
    // Curve base field
    private byte[] FP = null;
    // Curve 'a' parameter in the Weierstrass equation
    private byte[] A = null;
    // Curve 'b' parameter in the Weierstrass equation
    private byte[] B = null;
    // Curve generator
    private byte[] G = null;
    // Curve order
    private byte[] R = null;
    // Curve cofactor
    private byte K;

    /* Constants */
    // SECP384R1 point length including the prefix
    // Assuming that SECP384R1 is the biggest curve that will be used
    private static final short CURVE_MAX_POINT_LEN = 97;

    /* RAM */
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

    /**
     * Gets the curve parameters length.
     * @return curveLength Curve parameters length
     */
    protected short getCurveLength() {
        return curveLength;
    }

    /**
     * Sets the key curve parameters.
     * @param[in] key Elliptic curve private or public key
     */
    protected void setCurveParameters(ECKey key) {
        try {
            key.setA(A, (short) 0, (short) A.length);
            key.setB(B, (short) 0, (short) B.length);
            key.setFieldFP(FP, (short) 0, (short) FP.length);
            key.setG(G, (short) 0, (short) G.length);
            key.setR(R, (short) 0, (short) R.length);
            key.setK(K);
        } catch (Exception e) {
        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * Performs the scalar multiplication {scalar * G} where G is the curve generator.
     * @param[in] scalar  Curve scalar
     * @param[out] result Curve point result
     */
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

    /**
     * Performs the scalar multiplication {scalar * inPoint}.
     * @param[in] scalar    Curve Scalar
     * @param[in] inPoint   Curve point
     * @param[out] outPoint Curve point result
     */
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

    /**
     * Erases the Curve fields.
     */
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

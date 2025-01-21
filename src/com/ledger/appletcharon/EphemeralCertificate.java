package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

public class EphemeralCertificate {
    // Ephemeral certificate public key
    private ECPrivateKey privateKey;
    // Ephemeral certificate private key
    private ECPublicKey publicKey;
    // Card challenge
    private byte[] cardChallenge;
    // Card challenge length
    private static final byte CARD_CHALLENGE_LEN = 8;
    // Card ephemeral certificate role
    private byte cardCertEphRole;
    // Host challenge
    private byte[] hostChallenge;
    private static final byte MAX_HOST_CHALLENGE_LEN = 8;
    // Host challenge length
    private byte[] hostChallengeLength;
    // Crypto utility
    private CryptoUtil crypto;
    // Random data generator
    private RandomData randomData;

    // Constructor
    public EphemeralCertificate(CryptoUtil crypto, byte cardCertEphRole) {
        this.crypto = crypto;
        this.cardCertEphRole = cardCertEphRole;
        randomData = RandomData.getInstance(RandomData.ALG_TRNG);
        cardChallenge = JCSystem.makeTransientByteArray((short) CARD_CHALLENGE_LEN, JCSystem.CLEAR_ON_DESELECT);
        hostChallenge = JCSystem.makeTransientByteArray((short) MAX_HOST_CHALLENGE_LEN, JCSystem.CLEAR_ON_DESELECT);
        hostChallengeLength = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    protected void initData(byte[] buffer, short offset) {
        // Initialize curve
        if (crypto.getCurveId() != CryptoUtil.SECP256K1) {
            crypto.initCurve(CryptoUtil.SECP256K1);
        }
        // Generate key pair
        // We cannot call KeyBuilder.buildKey in the constructor (results in 0x6F00
        // error at install), so we do it here instead.
        if (privateKey == null) {
            privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                    crypto.getCurve().getCurveLength(), false);
        } else {
            privateKey.clearKey();
        }

        if (publicKey == null) {
            publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, crypto.getCurve().getCurveLength(), false);
        } else {
            publicKey.clearKey();
        }
        crypto.generateKeyPair(buffer, (short) 0, privateKey, publicKey);
        // Create new card challenge
        randomData.nextBytes(cardChallenge, (short) 0, CARD_CHALLENGE_LEN);
    }

    protected void setHostChallenge(byte[] hostChallenge, byte offset, byte length) {
        if (length > MAX_HOST_CHALLENGE_LEN) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopy(hostChallenge, offset, this.hostChallenge, (short) 0, length);
        hostChallengeLength[0] = length;

    }

    protected short getHostChallenge(byte[] outHostChallenge, short offset) {
        Util.arrayCopy(hostChallenge, (short) 0, outHostChallenge, offset, hostChallengeLength[0]);
        return hostChallengeLength[0];
    }

    protected short getCardChallenge(byte[] outCardChallenge, short offset) {
        Util.arrayCopy(cardChallenge, (short) 0, outCardChallenge, offset, CARD_CHALLENGE_LEN);
        return CARD_CHALLENGE_LEN;
    }

    protected ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    protected short getSignedCertificate(byte[] tmpBuffer, byte[] outCertificate, short offset, ECPrivateKey signingKey) {
        // Fill-in certificate data
        short outOffset = offset;
        outCertificate[outOffset++] = CARD_CHALLENGE_LEN;
        Util.arrayCopy(cardChallenge, (short) 0, outCertificate, outOffset, CARD_CHALLENGE_LEN);
        outOffset += CARD_CHALLENGE_LEN;
        short publicKeyLength = publicKey.getW(outCertificate, (short) (outOffset + 1));
        outCertificate[outOffset] = (byte) publicKeyLength;
        outOffset += 1 + publicKeyLength;
        // Prepare data to sign
        short dataLength = (short) (1 + CARD_CHALLENGE_LEN + hostChallengeLength[0] + publicKeyLength);
        tmpBuffer[0] = cardCertEphRole;
        Util.arrayCopy(cardChallenge, (short) 0, tmpBuffer, (short) 1, CARD_CHALLENGE_LEN);
        Util.arrayCopy(hostChallenge, (short) 0, tmpBuffer, (short) (1 + CARD_CHALLENGE_LEN), (short) hostChallengeLength[0]);
        publicKey.getW(tmpBuffer, (short) (1 + CARD_CHALLENGE_LEN + hostChallengeLength[0]));
        // Compute signature
        short signatureLength = crypto.computeSignatureWithKey(tmpBuffer, (short) 0, dataLength, outCertificate, (short) (outOffset + 1),
                signingKey);
        // Fill-in signature length
        outCertificate[outOffset] = (byte) signatureLength;
        outOffset += 1 + signatureLength;
        return (short) (outOffset - offset);
    }
}
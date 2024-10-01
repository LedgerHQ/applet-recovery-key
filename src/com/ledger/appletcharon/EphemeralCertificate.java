package com.ledger.appletcharon;

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
    // Host challenge length
    private byte[] hostChallengeLength;
    // Crypto utility
    private CryptoUtil crypto;

    // Constructor
    public EphemeralCertificate(CryptoUtil crypto, byte cardCertEphRole) {
        this.crypto = crypto;
        this.cardCertEphRole = cardCertEphRole;
    }

    protected void initData(byte[] buffer, short offset) {
        // Initialize curve
        crypto.initCurve(CryptoUtil.SECP256K1);
        // Generate key pair
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                crypto.getCurve().getCurveLength(), false);
        publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, crypto.getCurve().getCurveLength(),
                false);
        crypto.generateKeyPair(buffer, (short) 0, privateKey, publicKey);
        // Create new card challenge
        cardChallenge = JCSystem.makeTransientByteArray((short) CARD_CHALLENGE_LEN, JCSystem.CLEAR_ON_DESELECT);
        RandomData randomData = RandomData.getInstance(RandomData.ALG_TRNG);
        randomData.nextBytes(cardChallenge, (short) 0, CARD_CHALLENGE_LEN);
    }

    protected void setHostChallenge(byte[] hostChallenge, byte offset, byte length) {
        // Check if host challenge is not already set
        // If already set, throw an exception ?
        if (this.hostChallenge == null) {
            this.hostChallenge = JCSystem.makeTransientByteArray((short) length, JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(hostChallenge, offset, this.hostChallenge, (short) 0, length);
        if (this.hostChallengeLength == null) {
            this.hostChallengeLength = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        }
        this.hostChallengeLength[0] = length;
    }

    protected short getHostChallenge(byte[] outHostChallenge, short offset) {
        if (hostChallenge == null) {
            return 0;
        }
        Util.arrayCopy(hostChallenge, (short) 0, outHostChallenge, offset, hostChallengeLength[0]);
        return hostChallengeLength[0];
    }

    protected short getCardChallenge(byte[] outCardChallenge, short offset) {
        if (cardChallenge == null) {
            return 0;
        }
        Util.arrayCopy(cardChallenge, (short) 0, outCardChallenge, offset, CARD_CHALLENGE_LEN);
        return CARD_CHALLENGE_LEN;
    }

    protected ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    protected short getSignedCertificate(byte[] outCertificate, short offset, ECPrivateKey signingKey) {
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
        byte[] dataToSign = JCSystem.makeTransientByteArray(dataLength, JCSystem.CLEAR_ON_DESELECT);
        dataToSign[0] = cardCertEphRole;
        Util.arrayCopy(cardChallenge, (short) 0, dataToSign, (short) 1, CARD_CHALLENGE_LEN);
        Util.arrayCopy(hostChallenge, (short) 0, dataToSign, (short) (1 + CARD_CHALLENGE_LEN),
                (short) hostChallengeLength[0]);
        publicKey.getW(dataToSign, (short) (1 + CARD_CHALLENGE_LEN + hostChallengeLength[0]));
        // Compute signature
        short signatureLength = crypto.computeSignatureWithKey(dataToSign, (short) 0, dataLength, outCertificate,
                (short) (outOffset + 1), signingKey);
        // Fill-in signature length
        outCertificate[outOffset] = (byte) signatureLength;
        outOffset += 1 + signatureLength;
        return (short) (outOffset - offset);
    }
}
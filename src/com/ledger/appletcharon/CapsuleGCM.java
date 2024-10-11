package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

// Card Access Protocol for SeCure Ledger Exchange (CAPSULE)
// Uses Elliptic Curve Diffie-Hellman (ECDH) key agreement and AES-GCM authenticated encryption
public class CapsuleGCM {

    private KeyAgreement ecdhAgreement;
    private MessageDigest messageDigest;
    private AEADCipher aeadCipher;
    private byte[] sharedSecret;
    private byte[] sessionKeyRaw;
    private AESKey sessionKey;
    // Nonce consists of 8-byte random value and 4-byte message counter
    private byte[] nonce;
    private int messageCounter; // 4-byte counter
    private byte[] key_counter;

    private static final short KEY_COUNTER_LENGTH = 4;
    private static final short KEY_LENGTH = 32; // SHA-256 key length
    private static final short GCM_NONCE_LENGTH = 12;
    private static final short GCM_TAG_LENGTH = 16;
    private static final short SHARED_SECRET_LENGTH = 69; // Key counter + Prefix + X + Y

    public CapsuleGCM() {
        ecdhAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        try {
            aeadCipher = (AEADCipher) AEADCipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }
        messageCounter = 0;
    }

    protected void generateSessionKey(byte[] hostPublicKey, short hostPublicKeyOffset, short hostPublicKeyLength,
            ECPrivateKey cardPrivateEphemeralKey) {
        ecdhAgreement.init(cardPrivateEphemeralKey);

        // Reinit message counter
        messageCounter = 0;

        if (sharedSecret == null) {
            sharedSecret = JCSystem.makeTransientByteArray(SHARED_SECRET_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        if (key_counter == null) {
            key_counter = JCSystem.makeTransientByteArray(KEY_COUNTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }

        Util.arrayFill(key_counter, (short) 0, KEY_COUNTER_LENGTH, (byte) 0);
        Util.arrayCopy(key_counter, (short) 0, sharedSecret, (short) 0, KEY_COUNTER_LENGTH);

        ecdhAgreement.generateSecret(hostPublicKey, hostPublicKeyOffset, hostPublicKeyLength, sharedSecret,
                (short) KEY_COUNTER_LENGTH);

        if (sessionKeyRaw == null) {
            sessionKeyRaw = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }

        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, SHARED_SECRET_LENGTH, sessionKeyRaw, (short) 0);

        // Initialize AES key
        sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256,
                false);
        sessionKey.setKey(sessionKeyRaw, (short) 0);
    }

    protected short getRawSessionKey(byte[] buffer, short offset) {
        Util.arrayCopy(sessionKeyRaw, (short) 0, buffer, offset, KEY_LENGTH);
        return KEY_LENGTH;
    }

    protected short encryptData(byte[] plaintext, short plaintextOffset, short plaintextLength, byte[] ciphertext,
            short ciphertextOffset) {
        if (nonce == null) {
            // Throw an exception
        }
        // Increment the message counter and update the nonce
        messageCounter++;
        Util.setShort(nonce, (short) 8, (short) (messageCounter >>> 16)); // Upper 2 bytes of the counter
        Util.setShort(nonce, (short) 10, (short) (messageCounter & 0xFFFF)); // Lower 2 bytes of the counter
        // Initialize AEADCipher for encryption
        aeadCipher.init(sessionKey, Cipher.MODE_ENCRYPT, nonce, (short) 0, GCM_NONCE_LENGTH);
        // Encrypt plaintext
        short cipĥerTextLength = aeadCipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext,
                ciphertextOffset);
        // Retrieve tag and append it to the ciphertext
        aeadCipher.retrieveTag(ciphertext, (short) (ciphertextOffset + cipĥerTextLength), GCM_TAG_LENGTH);
        return (short) (cipĥerTextLength + GCM_TAG_LENGTH);
    }

    protected short decryptData(byte[] inData, short inOffset, short inDataLength, byte[] plaintext,
            short plaintextOffset) {
        if (nonce == null) {
            nonce = JCSystem.makeTransientByteArray(GCM_NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Nonce from the client are the first 12 bytes of the inBuffer
        Util.arrayCopy(inData, inOffset, nonce, (short) 0, GCM_NONCE_LENGTH);
        // Compute ciphertext length
        short ciphertextLength = (short) (inDataLength - GCM_TAG_LENGTH - GCM_NONCE_LENGTH);
        // Compute tag offset
        short tagOffset = (short) (inOffset + GCM_NONCE_LENGTH + ciphertextLength);
        // Compute tag length from inBuffer
        short tagLength = (short) (inDataLength - (tagOffset - inOffset));
        // Initialize AEADCipher for decryption
        aeadCipher.init(sessionKey, Cipher.MODE_DECRYPT, nonce, (short) 0, GCM_NONCE_LENGTH);
        // Decrypt ciphertext
        short plaintextLength = aeadCipher.doFinal(inData, (short) (inOffset + GCM_NONCE_LENGTH), ciphertextLength,
                plaintext, plaintextOffset);
        // Verify tag
        if (aeadCipher.verifyTag(inData, tagOffset, tagLength, GCM_TAG_LENGTH) == false) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return plaintextLength;
    }
}

package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class CapsuleCBC {
    private KeyAgreement ecdhAgreement;
    private MessageDigest messageDigest;
    private Cipher cipher;
    private Signature hmac;
    private byte[] sharedSecret;
    private byte[] rawEncSessionKey;
    private AESKey encSessionKey;
    private byte[] rawMacSessionKey;
    private HMACKey macSessionKey;
    private byte[] key_counter;
    private RandomData randomData;
    private byte[] iv;

    private static final short AES_CBC_BLOCK_SIZE = 16;
    private static final short AES_CBC_IV_LENGTH = 16;
    private static final short HMAC_LENGTH = 32;
    private static final short KEY_COUNTER_LENGTH = 4;
    private static final short KEY_LENGTH = 32; // SHA-256 key length
    private static final short SHARED_SECRET_LENGTH = 69; // Key counter + Prefix + X + Y

    public CapsuleCBC() {
        ecdhAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        // Use unpadded AES CBC because other padding methods actually just
        // do zero padding. We are doing our own ISO7816 padding.
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        randomData = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    }

    private short padISO7816(byte[] buffer, short offset, short length, short blockSize) {
        short paddingLength = (short) (blockSize - (length % blockSize));
        // Add the padding start marker: 0x80
        buffer[(short) (offset + length)] = (byte) 0x80;
        // Fill the remaining space with 0x00
        Util.arrayFillNonAtomic(buffer, (short) (offset + length + 1), (short) (paddingLength - 1), (byte) 0x00);
        return (short) (length + paddingLength);
    }

    private short unpadISO7816(byte[] buffer, short offset, short length) {
        if (length == 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Start from the end and search for the padding marker 0x80
        short paddingStart = (short) (offset + length - 1);
        // Look for the 0x80 marker
        while (paddingStart >= offset && buffer[paddingStart] == (byte) 0x00) {
            paddingStart--;
        }
        // Throw an exception if the padding marker is incorrect
        if (buffer[paddingStart] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return (short) (paddingStart - offset);
    }

    protected void generateSessionKeys(byte[] hostPublicKey, short hostPublicKeyOffset, short hostPublicKeyLength,
            ECPrivateKey cardPrivateEphemeralKey) {
        // Initialize ECDH key agreement
        ecdhAgreement.init(cardPrivateEphemeralKey);
        // Initialize shared secret byte array
        if (sharedSecret == null) {
            sharedSecret = JCSystem.makeTransientByteArray(SHARED_SECRET_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Initialize key counter byte array
        if (key_counter == null) {
            key_counter = JCSystem.makeTransientByteArray(KEY_COUNTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Fill key counter with zeros
        Util.arrayFill(key_counter, (short) 0, KEY_COUNTER_LENGTH, (byte) 0);
        Util.arrayCopy(key_counter, (short) 0, sharedSecret, (short) 0, KEY_COUNTER_LENGTH);
        // Generate shared secret
        ecdhAgreement.generateSecret(hostPublicKey, hostPublicKeyOffset, hostPublicKeyLength, sharedSecret,
                (short) KEY_COUNTER_LENGTH);
        // Initialize rawEncSessionKey byte array
        if (rawEncSessionKey == null) {
            rawEncSessionKey = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Compute SHA-256 hash of shared secret
        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, SHARED_SECRET_LENGTH, rawEncSessionKey, (short) 0);
        // Initialize AES key
        encSessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256,
                false);
        encSessionKey.setKey(rawEncSessionKey, (short) 0);
        // Increment key counter and update shared secret
        key_counter[3]++;
        Util.arrayCopy(key_counter, (short) 0, sharedSecret, (short) 0, KEY_COUNTER_LENGTH);
        // Initialize rawMacSessionKey byte array
        if (rawMacSessionKey == null) {
            rawMacSessionKey = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Compute SHA-256 hash of updated shared secret
        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, SHARED_SECRET_LENGTH, rawMacSessionKey, (short) 0);
        // Initialize HMAC key
        macSessionKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        // Use the first 8 bytes of the rawMacSessionKey as the HMAC key. Max size
        // allowed by
        // LENGTH_HMAC_SHA_256_BLOCK_64 is 64 bits.
        macSessionKey.setKey(rawMacSessionKey, (short) 0, (short) (macSessionKey.getSize() / 8));
    }

    protected short encryptData(byte[] plaintext, short plaintextOffset, short plaintextLength, byte[] ciphertext,
            short ciphertextOffset) {
        // Generate IV
        if (iv == null) {
            iv = JCSystem.makeTransientByteArray(AES_CBC_IV_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        randomData.nextBytes(iv, (short) 0, (short) iv.length);
        // Prepend IV to the ciphertext
        Util.arrayCopy(iv, (short) 0, ciphertext, ciphertextOffset, AES_CBC_IV_LENGTH);
        // Pad plaintext
        short paddedLength = padISO7816(plaintext, plaintextOffset, plaintextLength, (short) AES_CBC_BLOCK_SIZE);
        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) AES_CBC_IV_LENGTH);
        // Encrypt plaintext
        short outLength = cipher.doFinal(plaintext, plaintextOffset, paddedLength, ciphertext,
                (short) (ciphertextOffset + AES_CBC_IV_LENGTH));
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_SIGN);
        // Compute HMAC
        hmac.sign(ciphertext, (short) (ciphertextOffset + AES_CBC_IV_LENGTH), (short) outLength, ciphertext,
                (short) (ciphertextOffset + AES_CBC_IV_LENGTH + outLength));
        return (short) (outLength + AES_CBC_IV_LENGTH + HMAC_LENGTH);
    }

    protected short decryptData(byte[] inData, short inOffset, short inDataLength, byte[] plaintext,
            short plaintextOffset) {
        // Get IV from the first block of the ciphertext
        if (iv == null) {
            iv = JCSystem.makeTransientByteArray(AES_CBC_IV_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(inData, inOffset, iv, (short) 0, AES_CBC_IV_LENGTH);
        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_DECRYPT, iv, (short) 0, AES_CBC_IV_LENGTH);
        // Decrypt ciphertext
        short plaintextLength = cipher.doFinal(inData, (short) (inOffset + AES_CBC_IV_LENGTH),
                (short) (inDataLength - AES_CBC_IV_LENGTH - HMAC_LENGTH), plaintext, plaintextOffset);
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_VERIFY);
        // Verify HMAC
        if (hmac.verify(inData, (short) (inOffset + AES_CBC_IV_LENGTH),
                (short) (inDataLength - AES_CBC_IV_LENGTH - HMAC_LENGTH), inData,
                (short) (inOffset + inDataLength - HMAC_LENGTH), HMAC_LENGTH) == false) {
            // Throw an exception
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Unpad plaintext
        plaintextLength = unpadISO7816(plaintext, plaintextOffset, plaintextLength);
        return plaintextLength;
    }
}

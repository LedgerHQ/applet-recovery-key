package com.ledger.appletcharon;

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
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        randomData = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
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
        ecdhAgreement.generateSecret(hostPublicKey, hostPublicKeyOffset, hostPublicKeyLength, sharedSecret, (short) KEY_COUNTER_LENGTH);
        // Initialize rawEncSessionKey byte array
        if (rawEncSessionKey == null) {
            rawEncSessionKey = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        // Compute SHA-256 hash of shared secret
        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, SHARED_SECRET_LENGTH, rawEncSessionKey, (short) 0);
        // Initialize AES key
        encSessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
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
        macSessionKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
                false);
        // Use the first 8 bytes of the rawMacSessionKey as the HMAC key. Max size
        // allowed by
        // LENGTH_HMAC_SHA_256_BLOCK_64 is 64 bits.
        macSessionKey.setKey(rawMacSessionKey, (short) 0, (short) (macSessionKey.getSize() / 8));
    }

    protected short encryptData(byte[] plaintext, short plaintextOffset, short plaintextLength, byte[] ciphertext, short ciphertextOffset) {
        // Generate IV
        if (iv == null) {
            iv = JCSystem.makeTransientByteArray(AES_CBC_IV_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        randomData.nextBytes(iv, (short) 0, (short) iv.length);
        // Prepend IV to the ciphertext
        Util.arrayCopy(iv, (short) 0, ciphertext, ciphertextOffset, AES_CBC_IV_LENGTH);
        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) AES_CBC_IV_LENGTH);
        // Encrypt plaintext
        short outLength = cipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext,
                (short) (ciphertextOffset + AES_CBC_IV_LENGTH));
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_SIGN);
        // Compute HMAC
        hmac.sign(ciphertext, (short) (ciphertextOffset + AES_CBC_IV_LENGTH), (short) outLength, ciphertext,
                (short) (ciphertextOffset + AES_CBC_IV_LENGTH + outLength));
        return (short) (outLength + AES_CBC_IV_LENGTH + HMAC_LENGTH);
    }

    protected short decryptData(byte[] inData, short inOffset, short inDataLength, byte[] plaintext, short plaintextOffset) {
        // Get IV from the first block of the ciphertext
        if (iv == null) {
            iv = JCSystem.makeTransientByteArray(AES_CBC_IV_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        }
        Util.arrayCopy(inData, inOffset, iv, (short) 0, AES_CBC_IV_LENGTH);
        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_DECRYPT, iv, (short) 0, AES_CBC_IV_LENGTH);
        // Decrypt ciphertext
        short plaintextLength = 0;
        try {
            plaintextLength = cipher.doFinal(inData, (short) (inOffset + AES_CBC_IV_LENGTH),
                    (short) (inDataLength - AES_CBC_IV_LENGTH - HMAC_LENGTH), plaintext, plaintextOffset);
        } catch (Exception e) {
            ISOException.throwIt((short) com.ledger.appletcharon.AppletCharon.SW_INCORRECT_SCP_LEDGER);
        }
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_VERIFY);
        // Verify HMAC
        if (hmac.verify(inData, (short) (inOffset + AES_CBC_IV_LENGTH), (short) (inDataLength - AES_CBC_IV_LENGTH - HMAC_LENGTH), inData,
                (short) (inOffset + inDataLength - HMAC_LENGTH), HMAC_LENGTH) == false) {
            ISOException.throwIt((short) com.ledger.appletcharon.AppletCharon.SW_INCORRECT_SCP_LEDGER);
        }
        return plaintextLength;
    }

    protected boolean checkMAC(byte[] inData, short inOffset, short inDataLength, short inMACLength, short inMACOffset) {
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_VERIFY);
        // Verify HMAC
        return hmac.verify(inData, inOffset, inDataLength, inData, inMACOffset, inMACLength);
    }
}

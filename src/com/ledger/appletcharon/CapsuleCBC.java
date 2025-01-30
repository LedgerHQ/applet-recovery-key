package com.ledger.appletcharon;

import static com.ledger.appletcharon.Constants.SW_INCORRECT_SCP_LEDGER;

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
    private byte[] fixedInfo;
    private byte[] fixedInfoLength;

    private static final short AES_CBC_BLOCK_SIZE = 16;
    private static final short AES_CBC_IV_LENGTH = 16;
    private static final short HMAC_LENGTH = 32;
    private static final short KEY_COUNTER_LENGTH = 4;
    protected static final short KEY_LENGTH = 32; // SHA-256 key length
    private static final short SHARED_SECRET_LENGTH = 69; // Key counter + Prefix + X + Y
    private static final short MAX_FIXED_INFO_LENGTH = 48;

    public CapsuleCBC() {
        ecdhAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        randomData = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        fixedInfo = JCSystem.makeTransientByteArray(MAX_FIXED_INFO_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        fixedInfoLength = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        sharedSecret = JCSystem.makeTransientByteArray((short) (SHARED_SECRET_LENGTH + MAX_FIXED_INFO_LENGTH), JCSystem.CLEAR_ON_DESELECT);
        key_counter = JCSystem.makeTransientByteArray(KEY_COUNTER_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        rawEncSessionKey = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        rawMacSessionKey = JCSystem.makeTransientByteArray(KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        encSessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        macSessionKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
                false);
        iv = JCSystem.makeTransientByteArray(AES_CBC_IV_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    }

    protected void setFixedInfo(byte[] fixedInfoBuffer, short fixedInfoOffset, short fixedInfoLength) {
        // Clear previous fixed info buffer
        Util.arrayFill(fixedInfo, (short) 0, (short) fixedInfo.length, (byte) 0);
        Util.arrayCopy(fixedInfoBuffer, fixedInfoOffset, this.fixedInfo, (short) 0, fixedInfoLength);
        Util.setShort(this.fixedInfoLength, (short) 0, fixedInfoLength);
    }

    protected void generateSessionKeys(byte[] hostPublicKey, short hostPublicKeyOffset, short hostPublicKeyLength,
            ECPrivateKey cardPrivateEphemeralKey) {
        if (Util.getShort(fixedInfoLength, (short) 0) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Initialize ECDH key agreement
        ecdhAgreement.init(cardPrivateEphemeralKey);
        // Clear shared secret
        Util.arrayFill(sharedSecret, (short) 0, (short) sharedSecret.length, (byte) 0);
        short sharedSecretLength = (short) (SHARED_SECRET_LENGTH + Util.getShort(fixedInfoLength, (short) 0));
        // Fill key counter with zeros
        Util.arrayFill(key_counter, (short) 0, KEY_COUNTER_LENGTH, (byte) 0);
        Util.arrayCopy(key_counter, (short) 0, sharedSecret, (short) 0, KEY_COUNTER_LENGTH);
        // Generate shared secret
        ecdhAgreement.generateSecret(hostPublicKey, hostPublicKeyOffset, hostPublicKeyLength, sharedSecret, (short) KEY_COUNTER_LENGTH);
        // Copy fixed info to shared secret
        Util.arrayCopy(fixedInfo, (short) 0, sharedSecret, SHARED_SECRET_LENGTH, Util.getShort(fixedInfoLength, (short) 0));
        // Compute SHA-256 hash of shared secret
        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, sharedSecretLength, rawEncSessionKey, (short) 0);
        // Initialize AES key
        encSessionKey.setKey(rawEncSessionKey, (short) 0);
        // Erase rawEncSessionKey
        Util.arrayFill(rawEncSessionKey, (short) 0, (short) rawEncSessionKey.length, (byte) 0);
        // Increment key counter and update shared secret
        key_counter[3]++;
        Util.arrayCopy(key_counter, (short) 0, sharedSecret, (short) 0, KEY_COUNTER_LENGTH);
        // Compute SHA-256 hash of updated shared secret
        messageDigest.reset();
        messageDigest.doFinal(sharedSecret, (short) 0, sharedSecretLength, rawMacSessionKey, (short) 0);
        // Use the first 8 bytes of the rawMacSessionKey as the HMAC key. Max size
        // allowed by
        // LENGTH_HMAC_SHA_256_BLOCK_64 is 64 bits.
        macSessionKey.setKey(rawMacSessionKey, (short) 0, (short) (macSessionKey.getSize() / 8));
        // Erase rawMacSessionKey
        Util.arrayFill(rawMacSessionKey, (short) 0, (short) rawMacSessionKey.length, (byte) 0);
    }

    protected short encryptData(byte[] plaintext, short plaintextOffset, short plaintextLength, byte[] ciphertext, short ciphertextOffset) {
        randomData.nextBytes(iv, (short) 0, (short) iv.length);

        short currentOffset = ciphertextOffset;
        // Write IV length
        ciphertext[currentOffset++] = (byte) iv.length;

        // Write IV
        Util.arrayCopy(iv, (short) 0, ciphertext, currentOffset, AES_CBC_IV_LENGTH);
        currentOffset += AES_CBC_IV_LENGTH;

        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) AES_CBC_IV_LENGTH);

        // Reserve space for cipher length
        short cipherLengthOffset = currentOffset;
        currentOffset++;

        // Store start of cipher data position
        short cipherDataOffset = currentOffset;

        // Encrypt plaintext
        short cipherLength = cipher.doFinal(plaintext, plaintextOffset, plaintextLength, ciphertext, currentOffset);

        // Write cipher length
        ciphertext[cipherLengthOffset] = (byte) cipherLength;
        currentOffset += cipherLength;

        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_SIGN);

        // Compute HMAC on cipher part only
        short macLength = hmac.sign(ciphertext, cipherDataOffset, cipherLength, ciphertext, (short) (currentOffset + 1));

        // Write MAC length (using actual length from sign operation)
        ciphertext[currentOffset++] = (byte) macLength;

        // Return total length
        return (short) (currentOffset - ciphertextOffset + macLength);
    }

    protected short decryptData(byte[] inData, short inOffset, short inDataLength, byte[] plaintext, short plaintextOffset) {
        short currentOffset = inOffset;

        // Get and verify IV length
        byte ivLength = inData[currentOffset++];
        if (ivLength != AES_CBC_IV_LENGTH) {
            ISOException.throwIt((short) SW_INCORRECT_SCP_LEDGER);
        }

        // Get IV
        Util.arrayCopy(inData, currentOffset, iv, (short) 0, AES_CBC_IV_LENGTH);
        currentOffset += AES_CBC_IV_LENGTH;

        // Get cipher length
        short cipherLength = (short) (inData[currentOffset++] & 0xFF);

        // Get cipher data offset
        short cipherOffset = currentOffset;
        currentOffset += cipherLength;

        // Get and verify MAC length
        byte macLength = inData[currentOffset++];

        // Initialize HMAC key and verify MAC (on cipher part only)
        hmac.init(macSessionKey, Signature.MODE_VERIFY);
        boolean validMac = hmac.verify(inData, cipherOffset, cipherLength, inData, currentOffset, macLength);
        if (!validMac) {
            ISOException.throwIt((short) SW_INCORRECT_SCP_LEDGER);
        }

        // Initialize AES cipher
        cipher.init(encSessionKey, Cipher.MODE_DECRYPT, iv, (short) 0, AES_CBC_IV_LENGTH);

        // Decrypt ciphertext
        short plaintextLength = 0;
        try {
            plaintextLength = cipher.doFinal(inData, cipherOffset, cipherLength, plaintext, plaintextOffset);
        } catch (Exception e) {
            ISOException.throwIt((short) SW_INCORRECT_SCP_LEDGER);
        }

        return plaintextLength;
    }

    protected boolean checkMAC(byte[] inData, short inOffset, short inDataLength, short inMACOffset) {
        // Get MAC length
        short macLength = (short) (inData[inMACOffset] & 0xFF);
        // Initialize HMAC key
        hmac.init(macSessionKey, Signature.MODE_VERIFY);
        // Verify HMAC
        return hmac.verify(inData, inOffset, inDataLength, inData, (short) (inMACOffset + 1), macLength);
    }
}

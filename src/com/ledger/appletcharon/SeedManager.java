package com.ledger.appletcharon;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public class SeedManager {

    private static final short SEED_DATA_LENGTH_OFFSET = 0;
    private static final short SEED_DATA_OFFSET = 1;
    private static final short SEED_LENGTH = 32; // 256 bits = 32 bytes
    private static final byte[] BITCOIN_SEED = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };
    private static final int DERIVATION_PATH_INDEX_1 = 0x80000000;
    private static final int DERIVATION_PATH_INDEX_2 = 0x82000000;
    private static final int DERIVATION_PATH_INDEX_3 = 0x00000001;
    private static final byte DERIVATION_KEY_LENGTH = 16;

    protected AESKey seedKey;
    private Signature hmacSha512;
    private CryptoUtil crypto;
    private byte[] tempBuffer;
    private byte[] derivationBuffer;

    public SeedManager() {
        crypto = null;
        seedKey = null;
        // Initialize HMAC-SHA512
        hmacSha512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        // Initialize temporary buffers in transient memory
        tempBuffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        derivationBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }

    public void setCryptoUtil(CryptoUtil cryptoUtil) {
        crypto = cryptoUtil;
    }

    protected void setSeed(byte[] seed_data) {
        if (seedKey != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (seed_data[SEED_DATA_LENGTH_OFFSET] != SEED_LENGTH) {
            ISOException.throwIt(com.ledger.appletcharon.AppletCharon.SW_WRONG_LENGTH);
        }

        try {
            seedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // Store the seed as key data
            seedKey.setKey(seed_data, (short) SEED_DATA_OFFSET);
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }
    }

    protected byte restoreSeed(byte[] buffer, short offset) {
        try {
            // Retrieve the stored seed
            return seedKey.getKey(buffer, offset);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return 0;
    }

    protected void clearSeed() {
        if (seedKey == null) {
            return;
        }
        seedKey.clearKey();
        seedKey = null;
        JCSystem.requestObjectDeletion();
    }

    /**
     * Compute HMAC-SHA512
     */
    private void computeHmacSha512(byte[] key, short keyOffset, short keyLength, byte[] data, short dataOffset, short dataLength,
            byte[] output, short outputOffset) {
        // Create temporary HMAC key
        HMACKey hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
        hmacKey.setKey(key, keyOffset, keyLength);

        // Initialize HMAC with the key
        hmacSha512.init(hmacKey, Signature.MODE_SIGN);

        // Compute HMAC
        hmacSha512.sign(data, dataOffset, dataLength, output, outputOffset);

        // Clean up
        hmacKey.clearKey();
    }

    /**
     * Derive next key according to BIP32 spec Updates derivationBuffer in place
     * (first 32 bytes: private key, next 32 bytes: chain code)
     */
    private void deriveNextKey(int index) {
        // Determine buffer offset for private key and chain code
        byte keyOffset = 0;
        byte indexOffset = 32;
        // Check if the index is hardened
        if ((index & 0x80000000) != 0) {
            tempBuffer[0] = 0x00;
            keyOffset++;
            indexOffset++;
        }
        Util.arrayCopyNonAtomic(derivationBuffer, (short) 0, tempBuffer, (short) keyOffset, (short) 32);
        tempBuffer[indexOffset++] = (byte) ((index >> 24) & 0xFF);
        tempBuffer[indexOffset++] = (byte) ((index >> 16) & 0xFF);
        tempBuffer[indexOffset++] = (byte) ((index >> 8) & 0xFF);
        tempBuffer[indexOffset++] = (byte) (index & 0xFF);

        // H = HMAC-SHA512(key = chain_code, data = 0x00 || private_key || index)
        computeHmacSha512(derivationBuffer, (short) 32, (short) DERIVATION_KEY_LENGTH, // key = 16 most significant bytes of chain code
                tempBuffer, (short) 0, (short) indexOffset, // data = [0x00 if hardened] || private_key || index
                tempBuffer, (short) 64 // output to second half of tempBuffer
        );

        // new_private_key = (Hl + private_key) mod n
        if (crypto.getCurveId() != CryptoUtil.SECP256K1) {
            crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        crypto.add32bytesModR(tempBuffer, (short) 64, // Hl (first 32 bytes of HMAC output)
                derivationBuffer, (short) 0, // current private key
                derivationBuffer, (short) 0 // result: new private key
        );

        // new_chain_code = Hr (second 32 bytes of HMAC output)
        Util.arrayCopyNonAtomic(tempBuffer, (short) 96, // Hr (last 32 bytes of HMAC output)
                derivationBuffer, (short) 32, // new chain code
                (short) 32);
    }

    protected short signChallenge(byte[] challenge, short challengeOffset, short challengeLength, byte[] output, short outputOffset) {
        if (seedKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Step 1: Generate master key from seed
        seedKey.getKey(tempBuffer, (short) 0);
        computeHmacSha512(BITCOIN_SEED, (short) 0, (short) BITCOIN_SEED.length, tempBuffer, (short) 0, SEED_LENGTH, derivationBuffer,
                (short) 0);

        // Now derivationBuffer contains:
        // - [0-31]: master private key (mk)
        // - [32-63]: chain code (c)

        // Step 2: Derive key for path 0x80000000
        deriveNextKey(DERIVATION_PATH_INDEX_1);

        // Step 3: Derive key for path 0x82000000
        deriveNextKey(DERIVATION_PATH_INDEX_2);

        // Step 4: Final derivation for 0x00000001
        deriveNextKey(DERIVATION_PATH_INDEX_3);

        // Now derivationBuffer[0-31] contains the final private key for signing
        // Sign the challenge using ECDSA with SECP256K1
        if (crypto.getCurveId() != CryptoUtil.SECP256K1) {
            crypto.initCurve((byte) CryptoUtil.SECP256K1);
        }
        crypto.setSigningKey(derivationBuffer, (short) 0, (short) 32);
        short signatureLength = crypto.computeSignature(challenge, challengeOffset, challengeLength, output, outputOffset);

        // Clear data
        Util.arrayFillNonAtomic(tempBuffer, (short) 0, (short) tempBuffer.length, (byte) 0);
        Util.arrayFillNonAtomic(derivationBuffer, (short) 0, (short) derivationBuffer.length, (byte) 0);
        return signatureLength;
    }

    static Element save(SeedManager seedManager) {
        if (seedManager == null || seedManager.seedKey == null) {
            return null;
        }
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 0, (short) 1).write(seedManager.seedKey);
    }

    static SeedManager restore(Element element) {
        if (element == null) {
            return null;
        }
        SeedManager seedManager = new SeedManager();
        seedManager.seedKey = (AESKey) element.readObject();
        return seedManager;
    }
}

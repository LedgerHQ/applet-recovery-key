package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;

public class SeedManager {

    private static final short SEED_DATA_LENGTH_OFFSET = 0;
    private static final short SEED_DATA_OFFSET = 1;
    private static final short SEED_LENGTH = 32; // 256 bits = 32 bytes
    private AESKey seedKey;

    public SeedManager() {
        // Initialize the HMAC key object with the correct length
        seedKey = null;
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
            return (byte) seedKey.getKey(buffer, offset);
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
}
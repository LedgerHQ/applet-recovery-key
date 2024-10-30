package com.ledger.appletcharon;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;

public class SeedManager {

    private static final short SEED_LENGTH = 64; // 512 bits = 64 bytes
    private static final short SEED_DATA_LENGTH_OFFSET = 0;
    private static final short SEED_DATA_OFFSET = 1;
    private RSAPrivateKey seedKey;

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
            seedKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
            // Store the seed as key data
            seedKey.setExponent(seed_data, (short) SEED_DATA_OFFSET, (short) (SEED_LENGTH & 0x00FF));
        } catch (CryptoException e) {
            ISOException.throwIt(e.getReason());
        }
    }

    protected byte restoreSeed(byte[] buffer, short offset) {
        try {
            // Retrieve the stored seed
            return (byte) seedKey.getExponent(buffer, offset);
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
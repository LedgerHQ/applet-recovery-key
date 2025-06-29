/**
 * SPDX-FileCopyrightText: © 2024 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.SW_FATAL_ERROR_DURING_INIT;
import static com.ledger.appletrecoverykey.Constants.SW_WRONG_LENGTH;

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
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class SeedManager {

    private static final short SEED_DATA_LENGTH_OFFSET = 0;
    private static final short SEED_DATA_OFFSET = 1;
    private static final short SEED_LENGTH_12_WORDS = 16;
    private static final short SEED_LENGTH_18_WORDS = 24;
    protected static final short MAX_SEED_LENGTH = 32; // 256 bits = 32 bytes for 24 words
    private static final byte[] BITCOIN_SEED = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' };
    private static final byte[] SEED_CHECK_MSG = { 'S', 'e', 'c', 'u', 'r', 'e', ' ', 'L', 'e', 'd', 'g', 'e', 'r', ' ', 'K', 'e', 'y' };
    private static final int DERIVATION_PATH_INDEX_1 = 0x80000000;
    private static final int DERIVATION_PATH_INDEX_2 = 0x82000000;
    private static final int DERIVATION_PATH_INDEX_3 = 0x80000001;
    private static final byte DERIVATION_KEY_LENGTH = 16;
    private static final byte CMAC128_LENGTH = 16;

    protected AESKey seedKey;
    private HMACKey hmacKey;
    private byte seedLength;
    private byte[] seedCheckCMAC128;
    private Signature hmacSha512;
    private Signature aesCMAC128;
    private CryptoUtil crypto;
    private RandomData randomData;
    private byte[] tempBuffer;
    private byte[] derivationBuffer;
    private boolean seedSet;
    private FatalError fatalError;

    public SeedManager() {
        crypto = null;
        seedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        seedSet = false;
        seedLength = 0;
        seedCheckCMAC128 = new byte[CMAC128_LENGTH];
        hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
        hmacSha512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        aesCMAC128 = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_AES_CMAC128, Cipher.PAD_ISO9797_M2, false);
        tempBuffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        derivationBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        randomData = RandomData.getInstance(RandomData.ALG_TRNG);

    }

    public void setCryptoUtil(CryptoUtil cryptoUtil) {
        crypto = cryptoUtil;
    }

    private boolean isSeedLengthValid(short length) {
        return (length == MAX_SEED_LENGTH) || (length == SEED_LENGTH_12_WORDS) || (length == SEED_LENGTH_18_WORDS);
    }

    /**
     * Compute AES-CMAC-128 on the input message using an AES key object
     */
    private void computeAesCmac128(AESKey key, byte[] msg, short msgOffset, short msgLength, byte[] output, short outputOffset) {
        // Set AES key
        aesCMAC128.init(key, Signature.MODE_SIGN);

        // Compute CMAC
        aesCMAC128.sign(msg, msgOffset, msgLength, output, outputOffset);
    }

    protected void setSeed(byte[] seed_data) {
        if (seedSet == true) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        clearSeed();

        if (!isSeedLengthValid(seed_data[SEED_DATA_LENGTH_OFFSET])) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        try {
            JCSystem.beginTransaction();
            // Store the seed as key data
            seedKey.setKey(seed_data, (short) SEED_DATA_OFFSET);
            seedLength = seed_data[SEED_DATA_LENGTH_OFFSET];
            // Compute the CMAC-128 of the seed check msg using the seed as key.
            computeAesCmac128(seedKey, SEED_CHECK_MSG, (short) 0, (short) SEED_CHECK_MSG.length, seedCheckCMAC128, (short) 0);
            seedSet = true;
            JCSystem.commitTransaction();
        } catch (CryptoException e) {
            JCSystem.abortTransaction();
            throwFatalError();
        }
    }

    protected void checkSeed() {
        if (seedSet == false) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        try {
            if (!isSeedLengthValid(seedLength)) {
                throwFatalError();
            }
            // Compute the CMAC-128 of the seed check msg using the seed as key in
            // tempBuffer
            computeAesCmac128(seedKey, SEED_CHECK_MSG, (short) 0, (short) SEED_CHECK_MSG.length, tempBuffer, (short) 0);
            // Compare the computed CMAC-128 with the stored CMAC-128
            if (Util.arrayCompare(seedCheckCMAC128, (short) 0, tempBuffer, (short) 0, CMAC128_LENGTH) != 0) {
                throwFatalError();
            }
        } catch (Exception e) {
            throwFatalError();
        }
    }

    protected byte restoreSeed(byte[] buffer, short offset) {
        checkSeed();
        try {
            // Retrieve the stored seed
            seedKey.getKey(buffer, offset);
            return seedLength;
        } catch (CryptoException e) {
            throwFatalError();
        }
        return 0;
    }

    protected void clearSeed() {
        try {
            JCSystem.beginTransaction();
            randomData.nextBytes(tempBuffer, (short) 0, MAX_SEED_LENGTH);
            seedKey.clearKey();
            seedKey.setKey(tempBuffer, (short) 0);
            seedSet = false;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throwFatalError();
        }
    }

    protected boolean isSeedSet() {
        return seedSet;
    }

    public void setFatalError(FatalError fatalError) {
        this.fatalError = fatalError;
    }

    private void throwFatalError() {
        if (fatalError != null) {
            fatalError.throwIt();
        } else {
            ISOException.throwIt(SW_FATAL_ERROR_DURING_INIT);
        }
    }

    public void clearSeedOnFatalError() {
        // !!!!! WARNING !!!!!
        // ======================================
        // This method should only be called from
        // the applet's fatal error handler.
        // ======================================
        seedKey.clearKey();
        seedSet = false;
        seedLength = 0;
    }

    /**
     * Compute HMAC-SHA512
     */
    private void computeHmacSha512(byte[] key, short keyOffset, short keyLength, byte[] data, short dataOffset, short dataLength,
            byte[] output, short outputOffset) {
        // Set HMAC key
        hmacKey.clearKey();
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
        if (seedSet == false) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isSeedLengthValid(seedLength)) {
            throwFatalError();
        }

        // Step 1: Generate master key from seed
        seedKey.getKey(tempBuffer, (short) 0);
        computeHmacSha512(BITCOIN_SEED, (short) 0, (short) BITCOIN_SEED.length, tempBuffer, (short) (MAX_SEED_LENGTH - seedLength),
                seedLength, derivationBuffer, (short) 0);

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
        return UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 2, (short) 2).write(seedManager.seedSet)
                .write(seedManager.seedCheckCMAC128).write(seedManager.seedKey).write(seedManager.seedLength);
    }

    static SeedManager restore(Element element) {
        if (element == null) {
            return null;
        }
        SeedManager seedManager = new SeedManager();
        seedManager.seedSet = element.readBoolean();
        seedManager.seedCheckCMAC128 = (byte[]) element.readObject();
        seedManager.seedKey = (AESKey) element.readObject();
        seedManager.seedLength = (byte) element.readByte();
        return seedManager;
    }
}

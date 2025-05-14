/**
 * SPDX-FileCopyrightText: © 2024 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

package com.ledger.appletrecoverykey;

import static com.ledger.appletrecoverykey.Constants.SW_REFERENCE_DATA_NOT_FOUND;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public final class Utils {
    /**
     * Constructs a single TLV field with the given tag and value.
     *
     * @param tlvFields the byte array to write the TLV field to
     * @param offset    the starting offset to write the TLV field
     * @param tag       the tag (byte or short) for the TLV field
     * @param value     the value bytes for the TLV field
     * @return the new offset after writing the TLV field
     */
    public static short buildTLVField(byte[] tlvFields, short offset, Object tag, byte[] value) {
        return buildTLVField(tlvFields, offset, tag, value, (short) value.length);
    }

    /**
     * Constructs a single TLV field with the given tag and value.
     *
     * @param tlvFields the byte array to write the TLV field to
     * @param offset    the starting offset to write the TLV field
     * @param tag       the tag (byte or short) for the TLV field
     * @param value     the value bytes for the TLV field
     * @param length    the length of the value bytes to write
     * @return the new offset after writing the TLV field
     */
    public static short buildTLVField(byte[] tlvFields, short offset, Object tag, byte[] value, short length) {
        if (tag instanceof byte[]) {
            byte[] tagarray = (byte[]) tag;
            tlvFields[offset++] = (byte) tagarray[0];
        } else if (tag instanceof short[]) {
            short[] tagarray = (short[]) tag;
            tlvFields[offset++] = (byte) ((tagarray[0] >> 8) & 0xFF);
            tlvFields[offset++] = (byte) (tagarray[0] & 0xFF);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        tlvFields[offset++] = (byte) length;
        Util.arrayCopyNonAtomic(value, (short) 0, tlvFields, offset, length);
        return (short) (offset + length);
    }

    /**
     * Parses the TLV-encoded certificate given a tag and returns the offset of the
     * data length.
     * 
     * @param[in] tag Tag of the data
     * @param[in] tlvData TLV data buffer
     * @param[in] offset Offset of the TLV data
     * @param[in] length Length of the TLV data
     * @return Offset of the data length
     */
    public static short parseTLVGetOffset(byte tag, byte[] tlvData, short offset, short length) {
        short end = (short) (offset + length);
        boolean isTagFound = false;
        short outOffset = 0;
        short len = 0;

        while (!isTagFound && (offset < end)) {
            // Read the tag
            byte currentTag = (byte) (tlvData[offset] & 0xFF);
            offset++;

            if (currentTag == tag) {
                isTagFound = true;
                // Offset corresponding to the length
                outOffset = offset;
            }

            // Read the length
            len = (short) (tlvData[offset] & 0xFF);
            offset++;

            offset += len;
        }

        if (!isTagFound) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        // Return the offset
        return outOffset;
    }
}

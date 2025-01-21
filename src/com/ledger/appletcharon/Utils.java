package com.ledger.appletcharon;

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
        tlvFields[offset++] = (byte) value.length;
        Util.arrayCopyNonAtomic(value, (short) 0, tlvFields, offset, (short) length);
        return (short) (offset + value.length);
    }
}
package uniregistrar.driver.did.btcr2.util;

import org.apache.commons.codec.binary.Hex;

public class MulticodecUtil {

    public static final byte[] MULTICODEC_SECP256K1_PUB = new byte[] { (byte)0xe7, (byte)0x01 };    //  0xe7

    public static final byte[] MULTICODEC_SECP256K1_PRIV = new byte[] { (byte)0x81, (byte)0x26 };

    public static byte[] removeMulticodec(byte[] bytes, byte[] multicodec) {
        if (! isMulticodec(bytes, multicodec)) throw new IllegalArgumentException("Multicodec " + Hex.encodeHexString(multicodec) + " not found in " + Hex.encodeHexString(bytes));
        byte[] ret = new byte[bytes.length-multicodec.length];
        System.arraycopy(bytes, multicodec.length, ret, 0, bytes.length-multicodec.length);
        return ret;
    }

    private static boolean isMulticodec(byte[] bytes, byte[] multicodec) {
        for (int i=0; i<multicodec.length; i++) {
            if (multicodec[i] != bytes[i]) return false;
        }
        return true;
    }
}

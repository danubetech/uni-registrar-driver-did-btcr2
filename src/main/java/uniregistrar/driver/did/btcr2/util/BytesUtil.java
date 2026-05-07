package uniregistrar.driver.did.btcr2.util;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class BytesUtil {

    public static ByteBuffer byteBuffer(byte[] bytes) {
        return ByteBuffer.wrap(Arrays.copyOf(bytes, bytes.length));
    }
}

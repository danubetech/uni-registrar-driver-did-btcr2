package uniregistrar.driver.did.btcr2.util;

import java.util.Arrays;

public class BytesArray {

    private final byte[] bytes;

    private BytesArray(byte[] bytes) {
        this.bytes = bytes;
    }

    public static BytesArray bytesArray(byte[] bytes) {
        return new BytesArray(bytes);
    }

    public byte[] bytes() {
        return this.bytes;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        BytesArray that = (BytesArray) o;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return "BytesArray{" +
                "bytes=" + Arrays.toString(bytes) +
                '}';
    }
}

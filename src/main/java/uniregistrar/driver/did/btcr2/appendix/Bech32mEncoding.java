package uniregistrar.driver.did.btcr2.appendix;

import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Bech32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Bech32mEncoding {

    private static final Logger log = LoggerFactory.getLogger(Bech32mEncoding.class);

    public static String bech32Encode(String hrp, byte[] dataBytes) {
        String encodedString = Bech32.encodeBytes(Bech32.Encoding.BECH32M, hrp, dataBytes);
        if (log.isDebugEnabled()) log.debug("encodedString for " + hrp + " and " + Hex.encodeHexString(dataBytes) + ": " + encodedString);
        return encodedString;
    }
}

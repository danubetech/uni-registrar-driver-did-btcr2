package uniregistrar.driver.did.btcr2.appendix;

import org.bitcoinj.base.Bech32;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Bech32mDecoding {

    private static final Logger log = LoggerFactory.getLogger(Bech32mDecoding.class);

    public static Bech32.Bech32Data bech32Decode(String encodedString) throws AddressFormatException {
        Bech32.Bech32Data bech32Decoded = Bech32.decode(encodedString);
        if (log.isDebugEnabled()) log.debug("bech32Decoded for " + encodedString + ": " + bech32Decoded);
        return bech32Decoded;
    }
}

package uniregistrar.driver.did.btcr2.syntax;

import foundation.identity.did.DID;
import org.bitcoinj.base.Bech32;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.appendix.Bech32mDecoding;
import uniregistrar.driver.did.btcr2.data.records.GenesisBytesType;
import uniregistrar.driver.did.btcr2.data.records.IdentifierComponents;

public class DidBtcr2IdentifierDecoding {

    private static final Logger log = LoggerFactory.getLogger(DidBtcr2IdentifierDecoding.class);

    /*
     * did:btcr2 Identifier Decoding
     */

    // See https://dcdpr.github.io/did-btcr2/algorithms.html#did-btcr2-identifier-decoding
    public static IdentifierComponents didBtcr2IdentifierDecoding(DID identifier) throws RegistrationException {

        if (identifier == null) throw new IllegalArgumentException("Identifier cannot be null");

        if (! "did".equals(identifier.toUri().getScheme())) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid URI scheme (must be 'did'): " + identifier.getDidString());
        if (! "btcr2".equals(identifier.getMethodName())) throw new RegistrationException(RegistrationException.ERROR_METHOD_NOT_SUPPORTED, "Unsupported DID method (must be 'btcr2'): " + identifier.getDidString());

        // Decode the method-specific-id as a Bech32m encoded string [BIP350] to retrieve the unencoded data bytes and hrp

        Bech32.Bech32Data bech32Data;
        try {
            bech32Data = Bech32mDecoding.bech32Decode(identifier.getMethodSpecificId());
        } catch (AddressFormatException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Cannot bech32m-decode identifier: " + identifier.getMethodSpecificId(), ex);
        }
        String hrp = bech32Data.hrp;
        byte[] dataBytes = bech32Data.decode5to8();

        // Parse the unencoded data bytes according to Table 2: Unencoded Data Bytes to retrieve the
        // btcr2_version, network_value and genesis_bytes.

        byte btcr2_version_and_network_value_byte = dataBytes[0];
        byte[] genesis_bytes = Arrays.copyOfRange(dataBytes, 1, dataBytes.length);

        int btcr2_version = btcr2_version_and_network_value_byte & 0xF0;
        int network_value = btcr2_version_and_network_value_byte & 0x0F;

        // btcr2_version MUST be 0. Introduce version_number as btcr2_version + 1.

        if (btcr2_version != 0) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid version btcr2_version: " + btcr2_version);
        int version_number = btcr2_version + 1;

        // network_value MUST be one of the values in Table 1: Network Values.

        Network network_name;
        try {
            network_name = Network.valueOf(network_value);
        } catch (Exception ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'network_value' in " + identifier.getMethodSpecificId() + ": " + network_value);
        }

        // The hrp MUST be either "k" or "x".

        GenesisBytesType genesisBytesType = switch(hrp) {
            case "k" -> GenesisBytesType.SECP256K1PUBLICKEY;
            case "x" -> GenesisBytesType.SHA256HASH;
            default -> throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid 'hrp' in " + identifier.getMethodSpecificId() + ": " + bech32Data.hrp);
        };
        byte[] key_or_hash = genesis_bytes;

        // done

        IdentifierComponents identifierComponents = new IdentifierComponents(version_number, network_name, key_or_hash, genesisBytesType);
        if (log.isDebugEnabled()) log.debug("didBtcr2IdentifierDecoding: " + identifierComponents);
        return identifierComponents;
    }
}

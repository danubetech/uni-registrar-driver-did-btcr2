package uniregistrar.driver.did.btcr2.syntax;

import foundation.identity.did.DID;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Bech32;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.appendix.Bech32mDecoding;
import uniregistrar.driver.did.btcr2.syntax.records.IdentifierComponents;

public class DidBtcr2IdentifierDecoding {

    private static final Logger log = LoggerFactory.getLogger(DidBtcr2IdentifierDecoding.class);

    /*
     * 3.3 did:btcr2 Identifier Decoding
     */

    // See https://dcdpr.github.io/did-btcr2/#didbtcr2-identifier-decoding
    public static IdentifierComponents didBtcr2IdentifierDecoding(DID identifier) throws RegistrationException {

        if (identifier == null) throw new IllegalArgumentException("Identifier cannot be null");

        // Split identifier into an array of components at the colon : character.

        String[] components = identifier.getDidString().split(":");

        // If the length of the components array is not 3, raise invalidDid error.
        // If components[0] is not “did”, raise invalidDid error.
        // If components[1] is not “btcr2”, raise methodNotSupported error.

        if (components.length != 3) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid number of ':' characters (must be 3): " + identifier.getDidString());
        if (! "did".equals(components[0])) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid URI scheme (must be 'did'): " + identifier.getDidString());
        if (! "btcr2".equals(components[1])) throw new RegistrationException(RegistrationException.ERROR_METHOD_NOT_SUPPORTED, "Unsupported DID method (must be 'btcr2'): " + identifier.getDidString());

        // Set encodedString to components[2].

        String encodedString = components[2];

        // Pass encodedString to the Bech32m Decoding algorithm, retrieving hrp and dataBytes.
        // If the Bech32m decoding algorithm fails, raise invalidDid error.

        Bech32.Bech32Data bech32Data;
        try {
            bech32Data = Bech32mDecoding.bech32Decode(encodedString);
        } catch (AddressFormatException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Cannot bech32m-decode identifier: " + encodedString, ex);
        }
        String hrp = bech32Data.hrp;
        byte[] dataBytes = bech32Data.decode5to8();

        // Map hrp to idType from the following:

        String idType = switch(hrp) {
            case "k" -> "key";
            case "x" -> "external";
            default -> throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid 'hrp' value in " + encodedString + ": " + bech32Data.hrp);
        };

        // Set version to 1.

        Integer version = 1;

        // If at any point in the remaining steps there are not enough nibbles to complete the process, raise invalidDid error.

        // Start with the first nibble (the higher nibble of the first byte) of dataBytes.

        NibbleStream nibbleStream = new NibbleStream(dataBytes);
        byte nibble;

        do {

            nibble = nibbleStream.nextNibble();

            // Add the value of the current nibble to version.

            version += nibble;

            // If the value of the nibble is hexadecimal F (decimal 15), advance to the next nibble
            // (the lower nibble of the current byte or the higher nibble of the next byte) and
            // return to the previous step.

        } while (nibble == 0x0f);

        // If version is greater than 1, raise invalidDid error.

        if (version > 1) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'version' value in " + encodedString + ": " + version);

        // Advance to the next nibble and set networkValue to its value.

        byte networkValue = nibbleStream.nextNibble();

        // Map networkValue to network from the following:

        Network network;
        try {
            network = Network.valueOf(networkValue);
        } catch (Exception ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'network' value in " + encodedString + ": " + networkValue);
        }

        // If the number of nibbles consumed is odd:

        if (nibbleStream.isOdd()) {
            byte fillerNibble = nibbleStream.nextNibble();
            if (fillerNibble != 0) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid filler nibble in " + encodedString + ": " + fillerNibble);
        }

        // Set genesisBytes to the remaining dataBytes.

        byte[] genesisBytes = nibbleStream.remainingDataBytes();

        // If idType is “key” and genesisBytes is not a valid compressed secp256k1 public key, raise invalidDid error.

        if ("key".equals(idType)) {
            try {
                ECKey ecKey = ECKey.fromPublicOnly(genesisBytes);
                if (! ecKey.isCompressed()) throw new IllegalArgumentException("Not compressed");
            } catch (Exception ex) {
                throw new RegistrationException("Genesis bytes " + Hex.encodeHexString(genesisBytes) + " are not a valid compressed secp256k1 public key: " + ex.getMessage(), ex);
            }
        }

        // Return idType, version, network, and genesisBytes.

        IdentifierComponents identifierComponents = new IdentifierComponents(idType, version, network, genesisBytes);
        if (log.isDebugEnabled()) log.debug("didBtcr2IdentifierDecoding: " + identifierComponents);
        return identifierComponents;
    }

    /*
     * Helper methods
     */

    private static class NibbleStream {

        final private byte[] dataBytes;
        byte nextByteIndex = 0;
        boolean nextHighNibble = true;

        public NibbleStream(byte[] dataBytes) {
            this.dataBytes = dataBytes;
        }

        public byte nextNibble() throws RegistrationException {
            byte nextNibble = this.nextHighNibble ? higherNibble(this.dataBytes[this.nextByteIndex]) : lowerNibble(this.dataBytes[this.nextByteIndex]);
            this.nextHighNibble = ! this.nextHighNibble;
            if (this.nextHighNibble) this.nextByteIndex++;
            if (this.nextByteIndex >= this.dataBytes.length) throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Mot enough bytes left at index " + this.nextByteIndex + ": " + Hex.encodeHexString(this.dataBytes));
            return nextNibble;
        }

        public boolean isOdd() {
            return ! this.nextHighNibble;
        }

        public byte[] remainingDataBytes() {
            return Arrays.copyOfRange(this.dataBytes, this.nextByteIndex, this.dataBytes.length);
        }

        private static byte higherNibble(byte b) {
            return (byte) (b >> 4);
        }

        private static byte lowerNibble(byte b) {
            return (byte) (b & 15);
        }
    }
}

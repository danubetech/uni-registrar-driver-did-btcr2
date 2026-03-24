package uniregistrar.driver.did.btcr2.syntax;

import foundation.identity.did.DID;
import foundation.identity.did.parser.ParserException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.Network;
import uniregistrar.driver.did.btcr2.appendix.Bech32mEncoding;
import uniregistrar.driver.did.btcr2.data.records.GenesisBytesType;
import uniregistrar.driver.did.btcr2.data.records.IdentifierComponents;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class DidBtcr2IdentifierEncoding {

    private static final Logger log = LoggerFactory.getLogger(DidBtcr2IdentifierEncoding.class);

    /*
     * DID-BTCR2 Identifier Encoding
     */

    // See https://dcdpr.github.io/did-btcr2/algorithms.html#did-btcr2-identifier-encoding
    public static DID didBtcr2IdentifierEncoding(Integer version, Object networkValue, byte[] genesisBytes, GenesisBytesType genesisBytesType) throws RegistrationException {

        // The version_number value MUST be 1, declaring the encoding follows this specification.

        if (version > 1) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'version' value: " + version);
        }

        // If idType is not a valid value per above, raise invalidDid error.

        if (GenesisBytesType.SECP256K1PUBLICKEY != genesisBytesType && GenesisBytesType.SHA256HASH != genesisBytesType) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid 'idType' value: " + genesisBytesType);
        }

        // If network is not a valid value per above, raise invalidDid error.

        if (networkValue instanceof Network) networkValue = networkValue.toString();

        if (! (networkValue instanceof String networkValueString && Arrays.asList(Network.values()).contains(Network.valueOf(networkValueString))) && ! (networkValue instanceof Number)) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'network' value: " + networkValue);
        }

        // if network is a number and is outside the range of 1-8, raise invalidDid error.

        if (networkValue instanceof Number networkValueNumber && (networkValueNumber.intValue() < 1 || networkValueNumber.intValue() > 8)) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Unsupported 'network' number value: " + networkValueNumber);
        }

        // Map idType to hrp from the following:

        String hrp = switch (genesisBytesType) {
            case GenesisBytesType.SECP256K1PUBLICKEY -> "k";
            case GenesisBytesType.SHA256HASH -> "x";
            default -> throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Invalid 'idType' value in: " + genesisBytesType);
        };

        // Create an empty nibbles numeric array.

        ByteArrayOutputStream nibbles = new ByteArrayOutputStream();

        // Set fCount equal to (version - 1) / 15, rounded down.

        Integer fCount = (version - 1) / 15;

        // Append hexadecimal F (decimal 15) to nibbles fCount times.

        for (int i=0; i<fCount; i++) nibbles.write((byte) 0x0f);

        // Append (version - 1) mod 15 to nibbles.

        nibbles.write((version - 1) % 15);

        // If network is a string, append the numeric value from the following map to nibbles:

        if (networkValue instanceof String networkValueString) {
            nibbles.write(Network.valueOf(networkValueString).toInt());
        }

        // If network is a number, append network + 7 to nibbles.

        if (networkValue instanceof Number networkValueNumber) {
            nibbles.write(networkValueNumber.intValue() + 7);
        }

        // If the number of entries in nibbles is odd, append 0.

        if (nibbles.size() % 2 == 1) {
            nibbles.write((byte) 0x00);
        }

        // Create a dataBytes byte array from nibbles

        byte[] nibblesBytes = nibbles.toByteArray();
        ByteArrayOutputStream dataBytes = new ByteArrayOutputStream();
        for (int i=0; i<nibblesBytes.length; i+=2) {
            dataBytes.write((nibblesBytes[i] << 4) + nibblesBytes[i+1]);
        }

        // Append genesisBytes to dataBytes.

        try {
            dataBytes.write(genesisBytes);
        } catch (IOException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID, "Cannot write genesis bytes " + Hex.encodeHexString(genesisBytes) + ": " + ex.getMessage(), ex);
        }

        // Set identifier to “did:btcr2:”.

        String identifier = "did:btcr2:";

        // Pass hrp and dataBytes to the Bech32m Encoding algorithm, retrieving encodedString.

        String encodedString = Bech32mEncoding.bech32Encode(hrp, dataBytes.toByteArray());

        // Append encodedString to identifier.

        identifier += encodedString;

        // Return identifier.

        if (log.isDebugEnabled()) log.debug("didBtcr2IdentifierEncoding: " + identifier);
        try {
            return DID.fromString(identifier);
        } catch (ParserException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    // See https://dcdpr.github.io/did-btcr2/#didbtcr2-identifier-encoding
    public static DID didBtcr2IdentifierEncoding(IdentifierComponents identifierComponents) throws RegistrationException {

        return didBtcr2IdentifierEncoding(identifierComponents.version(), identifierComponents.network(), identifierComponents.genesisBytes(), identifierComponents.genesisBytesType());
    }
}

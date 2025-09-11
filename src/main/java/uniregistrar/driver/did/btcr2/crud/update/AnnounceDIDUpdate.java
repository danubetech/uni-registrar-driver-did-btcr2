package uniregistrar.driver.did.btcr2.crud.update;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.jsonld.JsonLDObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.connections.bitcoin.BitcoinConnector;
import uniregistrar.driver.did.btcr2.connections.ipfs.IPFSConnection;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class AnnounceDIDUpdate {

    private static final Logger log = LoggerFactory.getLogger(AnnounceDIDUpdate.class);

    private Update update;
    private BitcoinConnector bitcoinConnector;
    private IPFSConnection ipfsConnection;

    public AnnounceDIDUpdate(Update update, BitcoinConnector bitcoinConnector, IPFSConnection ipfsConnection) {
        this.update = update;
        this.bitcoinConnector = bitcoinConnector;
        this.ipfsConnection = ipfsConnection;
    }

    /*
     * 4.3.3 Announce DID Update
     */

    // See https://dcdpr.github.io/did-btcr2/#announce-did-update
    public List<Map<String, Object>> announceDIDUpdate(DID identifier, DIDDocument sourceDocument, List<URI> beaconIds, JsonLDObject btcr2Update, /* TODO: extra, not in spec */ Map<String, Object> didDocumentMetadata) throws RegistrationException {
        if (log.isDebugEnabled()) log.debug("announceDIDUpdate ({}, {}, {}, {})", identifier, sourceDocument, beaconIds, btcr2Update);

        // Set beaconServices to an empty array.

        List<Service> beaconServices = new LinkedList<>();

        // Set signalMetadata to an empty array.

        List<Map<String, Object>> signalsMetadata = new LinkedList<>();

        // For beaconId in beaconIds:

        for (URI beaconId : beaconIds) {

            // Find beaconService in sourceDocument.service with an id property equal to beaconId.

            Service beaconService = sourceDocument.getServices().stream().filter(s -> beaconId.equals(s.getId())).findAny().orElse(null);

            // If no beaconService MUST throw beaconNotFound error.

            if (beaconService == null) throw new RegistrationException("beaconNotFound", "No beacon found for beaconId " + beaconId);

            // Push beaconService to beaconServices.

            beaconServices.add(beaconService);
        }

        // For beaconService in beaconServices:

        for (Service beaconService : beaconServices) {

            // Set signalMetadata to null.

            Map<String, Object> signalMetadata = null;

            // If beaconService.type == SingletonBeacon:

            if ("SingletonBeacon".equals(beaconService.getType())) {

                // Set signalMetadata to the result of passing beaconService and btcr2Update to the
                // [Broadcast Singleton Beacon Signal] algorithm.

                // TODO
                signalMetadata = Collections.emptyMap();

                // Else If beaconService.type == CIDAggregateBeacon:
            } else if ("CIDAggregateBeacon".equals(beaconService.getType())) {

                // Set signalMetadata to the result of passing btcr2Identifier, beaconService and btcr2Update to the
                // [Broadcast CIDAggregate Beacon Signal] algorithm.

                // TODO
                signalMetadata = Collections.emptyMap();

                // Else If beaconService.type ==  SMTAggregateBeacon:
            } else if ("CIDAggregateBeacon".equals(beaconService.getType())) {

                // Set signalMetadata to the result of passing btcr2Identifier, beaconService and btcr2Update to the
                // [Broadcast SMTAggregate Beacon Signal] algorithm.

                // TODO
                signalMetadata = Collections.emptyMap();

                // Else:
            } else {

                // MUST throw invalidBeacon error.

                throw new RegistrationException("invalidBeacon", "Invalid beacon: " + beaconService.getType());
            }

            // Merge signalMetadata into signalsMetadata.

            signalsMetadata.add(signalMetadata);
        }

        // Return signalsMetadata

        if (log.isDebugEnabled()) log.debug("announceDIDUpdate: " + signalsMetadata);
        return signalsMetadata;
    }

    /*
     * Getters and setters
     */

    public Update getUpdate() {
        return this.update;
    }

    public void setUpdate(Update update) {
        this.update = update;
    }

    public BitcoinConnector getBitcoinConnector() {
        return bitcoinConnector;
    }

    public void setBitcoinConnector(BitcoinConnector bitcoinConnector) {
        this.bitcoinConnector = bitcoinConnector;
    }

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}

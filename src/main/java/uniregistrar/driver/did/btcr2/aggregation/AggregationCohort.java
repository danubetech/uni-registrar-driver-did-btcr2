package uniregistrar.driver.did.btcr2.aggregation;

import foundation.identity.did.DID;
import org.bitcoinj.base.Address;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.data.json.SMTProof;

import java.util.List;
import java.util.Map;

public record AggregationCohort(
        BeaconType beaconType,
        List<byte[]> schnorrPublicKeys,
        Address beaconAddress,

        // For a CAS Beacon:

        Map<DID, byte[]> casUpdateHashes,

        // For an SMT Beacon:

        Map<byte[], byte[]> smtUpdateHashes,
        Map<byte[], String> smtNonces,

        // For a CAS Beacon:
        // For an SMT Beacon:

        List<String> musig2Nonces,

        // For a CAS Beacon, the request signal confirmation message contains:

        Map<DID, byte[]> beaconAnnouncementMap,

        // For an SMT Beacon, the request signal confirmation message contains:

        Map<byte[], SMTProof> smtProof,

        // For a CAS Beacon, the request signal confirmation message contains:
        // For an SMT Beacon, the request signal confirmation message contains:

        byte[] unsignedBeaconSignal,
        String musig2AggregatedNonce
        ) {
}

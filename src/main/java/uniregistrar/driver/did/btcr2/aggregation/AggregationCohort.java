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
        Map<DID, byte[]> casUpdateHashes,
        Map<byte[], byte[]> smtUpdateHashes,
        List<String> musig2Nonces,
        Map<DID, byte[]> beaconAnnouncementMap,
        Map<byte[], SMTProof> smtProof,
        byte[] unsignedBeaconSignal,
        String musig2AggregatedNonce
        ) {
}

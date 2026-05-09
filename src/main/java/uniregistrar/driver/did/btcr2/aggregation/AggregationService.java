package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.Network;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import foundation.identity.did.Service;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.uri.BitcoinURIParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;
import uniregistrar.driver.did.btcr2.crud.update.UpdateProcessUpdateSignPayload;

import java.net.URI;
import java.util.concurrent.TimeUnit;

public class AggregationService {

    private static final Logger log = LoggerFactory.getLogger(UpdateProcessUpdateSignPayload.class);

    private static final Cache<String, AggregationCohort> aggregationCohorts = Caffeine.newBuilder()
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    // for now for testing
    private static void checkTestAggregationCohorts() {
        if (! containsAggregationCohort("cohort-mutinynet-cas-1")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-cas-1", Network.mutinynet, 1, BeaconType.CAS, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-smt-1")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-smt-1", Network.mutinynet, 1, BeaconType.SMT, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-cas-2")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-cas-2", Network.mutinynet, 2, BeaconType.CAS, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-smt-2")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-smt-2", Network.mutinynet, 2, BeaconType.SMT, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-cas-3")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-cas-3", Network.mutinynet, 2, BeaconType.CAS, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-smt-3")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-smt-3", Network.mutinynet, 2, BeaconType.SMT, ScriptType.P2TR));
        }
    }

    public static void addAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.put(aggregationCohort.getId(), aggregationCohort);
    }

    public static AggregationCohort getAggregationCohort(String id) {
        checkTestAggregationCohorts();
        return aggregationCohorts.getIfPresent(id);
    }

    public static boolean containsAggregationCohort(String id) {
        return aggregationCohorts.getIfPresent(id) != null;
    }

    public static AggregationCohort findByBeaconAddress(Address beaconAddress) {
        AggregationCohort aggregationCohort = aggregationCohorts.asMap().values().stream().filter(x -> beaconAddress.equals(x.getBeaconAddress())).findFirst().orElse(null);
        if (log.isDebugEnabled()) log.debug("For beacon address {} found aggregation cohort: {}", beaconAddress, aggregationCohort);
        return aggregationCohort;
    }

    public static AggregationCohort findByBeaconService(Service beaconService) throws RegistrationException {
        URI serviceEndpoint = (URI) beaconService.getServiceEndpoint();
        BitcoinURI bitcoinURI;
        try {
            bitcoinURI = serviceEndpoint == null ? null : BitcoinURI.of(serviceEndpoint.toString());
        } catch (BitcoinURIParseException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_OPTIONS, "Beacon service endpoint " + serviceEndpoint + " has invalid Bitcoin URI: " + ex.getMessage(), ex);
        }
        Address beaconAddress = bitcoinURI == null ? null : bitcoinURI.getAddress();
        if (log.isDebugEnabled()) log.debug("For beacon service {} found beacon address: {}", beaconService, beaconAddress);
        return findByBeaconAddress(beaconAddress);
    }

    public static void removeAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.invalidate(aggregationCohort.getId());
    }
}

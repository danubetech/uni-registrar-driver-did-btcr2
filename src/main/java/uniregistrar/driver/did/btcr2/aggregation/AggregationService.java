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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AggregationService {

    private static final Logger log = LoggerFactory.getLogger(UpdateProcessUpdateSignPayload.class);

    private static final Pattern COHORT_ID_PATTERN = Pattern.compile("^cohort-([a-z0-9]+)-([a-z0-9]{3})-([0-9]+)(-([a-z0-9]+))?$");

    private static final Cache<String, AggregationCohort> aggregationCohorts = Caffeine.newBuilder()
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    private static void addAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.put(aggregationCohort.getId(), aggregationCohort);
    }

    public static AggregationCohort getAggregationCohort(String id) {
        Matcher matcher = COHORT_ID_PATTERN.matcher(id);
        if (! matcher.matches()) throw new IllegalArgumentException("Invalid aggregation cohort ID: " + id);
        String networkString = matcher.group(1);
        String beaconTypeString = matcher.group(2);
        String maxSizeString = matcher.group(3);
        Network network;
        BeaconType beaconType;
        int maxSize;
        try {
            network = Network.valueOf(networkString);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid aggregation network string: " + networkString);
        }
        try {
            beaconType = switch (beaconTypeString) {
                case "cas" -> BeaconType.CAS;
                case "smt" -> BeaconType.SMT;
                default -> throw new IllegalArgumentException();
            };
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid aggregation beacon type string: " + beaconTypeString);
        }
        try {
            maxSize = Integer.parseInt(maxSizeString);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid aggregation max size string: " + maxSizeString);
        }
        return aggregationCohorts.get(id, (aggregationCohortId) -> new AggregationCohort(aggregationCohortId, network, maxSize, beaconType, ScriptType.P2TR));
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

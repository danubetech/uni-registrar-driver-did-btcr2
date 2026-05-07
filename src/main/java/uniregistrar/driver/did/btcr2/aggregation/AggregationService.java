package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.Network;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.ScriptType;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;

import java.util.concurrent.TimeUnit;

public class AggregationService {

    private static final Cache<String, AggregationCohort> aggregationCohorts = Caffeine.newBuilder()
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    // for now for testing
    private static void checkTestAggregationCohorts() {
        if (! containsAggregationCohort("cohort-mutinynet-01")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-01", Network.mutinynet, 2, BeaconType.CAS, ScriptType.P2TR));
        }
        if (! containsAggregationCohort("cohort-mutinynet-02")) {
            addAggregationCohort(new AggregationCohort("cohort-mutinynet-02", Network.mutinynet, 2, BeaconType.SMT, ScriptType.P2TR));
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

    public static AggregationCohort findByBeaconAddress(Address  beaconAddress) {
        return aggregationCohorts.asMap().values().stream().filter(x -> beaconAddress.equals(x.getBeaconAddress())).findFirst().orElse(null);
    }

    public static void removeAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.invalidate(aggregationCohort.getId());
    }
}

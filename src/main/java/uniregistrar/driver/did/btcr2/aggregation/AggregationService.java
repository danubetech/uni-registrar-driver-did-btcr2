package uniregistrar.driver.did.btcr2.aggregation;

import com.danubetech.btc.connection.Network;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.bitcoinj.base.ScriptType;
import uniregistrar.driver.did.btcr2.beacons.BeaconType;

import java.util.concurrent.TimeUnit;

public class AggregationService {

    private static final Cache<String, AggregationCohort> aggregationCohorts = Caffeine.newBuilder()
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    static {
        // for now for testing
        addAggregationCohort(new AggregationCohort("cohort-mutinynet-01", Network.mutinynet, 2, BeaconType.CAS, ScriptType.P2TR));
        addAggregationCohort(new AggregationCohort("cohort-mutinynet-02", Network.mutinynet, 2, BeaconType.SMT, ScriptType.P2TR));
    }

    public static void addAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.put(aggregationCohort.getId(), aggregationCohort);
    }

    public static AggregationCohort getAggregationCohort(String id) {
        return aggregationCohorts.getIfPresent(id);
    }

    public static void removeAggregationCohort(AggregationCohort aggregationCohort) {
        aggregationCohorts.invalidate(aggregationCohort.getId());
    }
}

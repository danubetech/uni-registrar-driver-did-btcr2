package uniregistrar.driver.did.btcr2.beacons;

import foundation.identity.did.Service;

public enum BeaconType {
    SINGLETON("SingletonBeacon"),
    CAS("CASBeacon"),
    SMT("SMTBeacon");

    private final String serviceType;

    BeaconType(String serviceType) {
        this.serviceType = serviceType;
    }

    public static BeaconType fromServiceType(String serviceType) {
        if (SINGLETON.getServiceType().equals(serviceType)) return SINGLETON;
        if (CAS.getServiceType().equals(serviceType)) return CAS;
        if (SMT.getServiceType().equals(serviceType)) return SMT;
        throw new IllegalArgumentException("Invalid beacon service type: " + serviceType);
    }

    public static boolean isValid(String serviceType) {
        return SINGLETON.getServiceType().equals(serviceType) || CAS.getServiceType().equals(serviceType) || SMT.getServiceType().equals(serviceType);
    }

    public static boolean isValid(Service service) {
        return isValid(service.getType());
    }

    public String getServiceType() {
        return serviceType;
    }
}

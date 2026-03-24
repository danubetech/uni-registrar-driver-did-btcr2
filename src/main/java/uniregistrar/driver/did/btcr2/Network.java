package uniregistrar.driver.did.btcr2;

import org.bitcoinj.base.BitcoinNetwork;

public enum Network {

    bitcoin,
    signet,
    regtest,
    testnet3,
    testnet4,
    mutinynet,
    reserved6,
    reserved7,
    reserved8,
    reserved9,
    reservedA,
    reservedB,
    custom1,
    custom2,
    custom3;

    public static Network valueOf(Object value) {
        if (value instanceof String) return Network.valueOf((String) value);
        if (value instanceof Number) return Network.valueOf(((Number) value).byteValue());
        throw new IllegalArgumentException("Unsupported value type: " + value.getClass().getName());
    }

    public static Network valueOf(Byte byteValue) {
        return switch(byteValue) {
            case 0x00 -> Network.bitcoin;
            case 0x01 -> Network.signet;
            case 0x02 -> Network.regtest;
            case 0x03 -> Network.testnet3;
            case 0x04 -> Network.testnet4;
            case 0x05 -> Network.mutinynet;
            case 0x06 -> Network.reserved6;
            case 0x07 -> Network.reserved7;
            case 0x08 -> Network.reserved8;
            case 0x09 -> Network.reserved9;
            case 0x0A -> Network.reservedA;
            case 0x0B -> Network.reservedB;
            case 0x0C -> Network.custom1;
            case 0x0D -> Network.custom2;
            case 0x0E -> Network.custom3;
            default -> throw new IllegalArgumentException("Unsupported 'network' value: " + byteValue);
        };
    }

    public int toInt() {
        return switch (this) {
            case bitcoin -> 0x00;
            case signet -> 0x01;
            case regtest -> 0x02;
            case testnet3 -> 0x03;
            case testnet4 -> 0x04;
            case mutinynet -> 0x05;
            case reserved6 -> 0x06;
            case reserved7 -> 0x07;
            case reserved8 -> 0x08;
            case reserved9 -> 0x09;
            case reservedA -> 0x0a;
            case reservedB -> 0x0b;
            case custom1 -> 0x0c;
            case custom2 -> 0x0d;
            case custom3 -> 0x0e;
        };
    }

    public BitcoinNetwork toBitcoinjNetwork() {
        return switch (this) {
            case bitcoin -> BitcoinNetwork.MAINNET;
            case signet -> BitcoinNetwork.SIGNET;
            case regtest -> BitcoinNetwork.REGTEST;
            case testnet3 -> BitcoinNetwork.TESTNET;
            case testnet4 -> BitcoinNetwork.TESTNET;   /* TODO: what is the difference between v3 and v4 ? */
            case mutinynet -> BitcoinNetwork.SIGNET;
            default -> throw new IllegalArgumentException("Unknown 'network': " + this);
        };
    }
}

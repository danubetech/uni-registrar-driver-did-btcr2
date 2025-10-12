# Universal Registrar Driver: did:btcr2

This is a [Universal Registrar](https://github.com/decentralized-identity/universal-registrar/) driver for **did:btcr2** identifiers.

(work in progress)

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [DID Method Specification](https://dcdpr.github.io/did-btcr2/)

## Build and Run (Docker)

```
docker compose build
docker compose up
```

## Example Requests

```shell
curl -X POST "http://localhost:9080/1.0/create?method=btcr2" \
     -H "Content-Type: application/json" \
     -d '{
       "didDocument": {
         "@context": ["https://www.w3.org/TR/did-1.1", "https://btcr2.dev/context/v1"]
       },
       "options": {
         "clientSecretMode": true,
         "network": "mutinynet"
       },
       "secret": { }
     }'
```

```shell
curl -X POST "http://localhost:9080/1.0/create?method=btcr2" \
     -H "Content-Type: application/json" \
     -d '{
       "didDocument" : {
         "@context": ["https://www.w3.org/TR/did-1.1", "https://btcr2.dev/context/v1"],
         "verificationMethod" : [ {
           "type" : "Multikey",
           "id" : "#initialKey",
           "publicKeyMultibase" : "zQ3shrogQZQDjQe6boF6Sas9occwW7rZVVLR3qQ85qt7JHXq4"
         } ],
         "assertionMethod" : [ "#initialKey" ],
         "capabilityDelegation" : [ "#initialKey" ],
         "capabilityInvocation" : [ "#initialKey" ],
         "authentication" : [ "#initialKey" ]
       },
       "options" : {
         "clientSecretMode" : true,
         "network" : "mutinynet"
       },
       "secret" : { }
     }'
```

## Driver Environment Variables

The driver recognizes the following environment variables:

### `uniregistrar_driver_did_btcr2_bitcoinConnections`

* Specifies how the driver interacts with the Bitcoin blockchain.
* Possible values:
    * `bitcoind`: Connects to a [bitcoind](https://bitcoin.org/en/full-node) instance via JSON-RPC
    * `btcd`: Connects to a [btcd](https://github.com/btcsuite/btcd) instance via JSON-RPC
    * `bitcoinj`: Connects to Bitcoin using a local [bitcoinj](https://bitcoinj.github.io/) client
    * `blockcypherapi`: Connects to [BlockCypher's API](https://www.blockcypher.com/dev/bitcoin/)
    * `esploraelectrsrest`: Connects to Esplora/Electrs REST API
* Default value: `bitcoind`

### `uniregistrar_driver_did_btcr2_bitcoinConnectionsUrls`

* Specifies the JSON-RPC URLs of the Bitcoin connections.

### `uniregistrar_driver_did_btcr2_bitcoinConnectionsCerts`

* Specifies the server TLS certificates of the Bitcoin connections.
* Default value: ``

## Driver Input Options

```
{
    "network": "mutinynet"
}
```

* `network`: The name of the network where a DID should be registered. Values depend on `bitcoinConnections` environment variable, but are typically: `bitcoin`, `testnet3`, `signet`, `mutinynet`.

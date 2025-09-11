package uniregistrar.driver.did.btcr2.appendix;

import foundation.identity.did.DID;
import foundation.identity.jsonld.JsonLDObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class DeriveRootCapabilityFromDidBtcr2Identifier {

    private static final Logger log = LoggerFactory.getLogger(DeriveRootCapabilityFromDidBtcr2Identifier.class);

    /*
     * 11.4.1 Derive Root Capability from did:btcr2 Identifier
     */

    // See https://dcdpr.github.io/did-btcr2/#derive-root-capability-from-didbtcr2-identifier
    public static JsonLDObject deriveRootCapabilityFromDidBtcr2Identifier(DID identifier) {
        if (log.isDebugEnabled()) log.debug("deriveRootCapabilityFromDidBtcr2Identifier ({})", identifier);

        // Define rootCapability as an empty object.

        Map<String, Object> rootCapability = new LinkedHashMap<>();

        // Set rootCapability.@context to ‘https://w3id.org/zcap/v1’.

        rootCapability.put("@context", "https://w3id.org/zcap/v1");

        // Set encodedIdentifier to result of calling algorithm encodeURIComponent(identifier).

        String encodedIdentifier = URLEncoder.encode(identifier.getDidString(), StandardCharsets.UTF_8);

        // Set rootCapability.id to urn:zcap:root:${encodedIdentifier}.

        rootCapability.put("id", "urn:zcap:root:" + encodedIdentifier);

        // Set rootCapability.controller to identifier.

        rootCapability.put("controller", identifier.getDidString());

        // Set rootCapability.invocationTarget to identifier.

        rootCapability.put("invocationTarget", identifier.getDidString());

        // Return rootCapability.

        JsonLDObject jsonldRootCapability = JsonLDObject.fromJsonObject(rootCapability);
        if (log.isDebugEnabled()) log.debug("deriveRootCapabilityFromDidBtcr2Identifier: " + jsonldRootCapability);
        return jsonldRootCapability;
    }
}

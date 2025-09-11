package uniregistrar.driver.did.btcr2.util;

import uniregistrar.openapi.model.VerificationMethodTemplate;

import java.util.List;
import java.util.Map;

public class VerificationMethodTemplateUtil {

    private static final VerificationMethodTemplate initialVerificationMethodTemplate;

    static {

        String id = "#initialKey";
        String type = "Multikey";
        String controller = null;
        Map<String, Object> publicKeyJwk = Map.of("kty", "EC", "crv", "secp256k1");
        List<String> purpose = List.of( "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation");

        initialVerificationMethodTemplate = new VerificationMethodTemplate()
                .id(id)
                .type(type)
                .controller(controller)
                .publicKeyJwk(publicKeyJwk)
                .purpose(purpose);
    }

    public static VerificationMethodTemplate createInitialVerificationMethodTemplate() {
        return initialVerificationMethodTemplate;
    }

    public static VerificationMethodTemplate createFinishedVerificationMethodTemplate(String did) {
        return new VerificationMethodTemplate()
                .id(did + "#initialKey")
                .type(null)
                .controller(did)
                .publicKeyJwk(null)
                .purpose(null);
    }
}

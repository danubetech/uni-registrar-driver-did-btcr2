package uniregistrar.driver.did.btcr2.ledger;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.jsonld.DIDContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class DidDocUnAssembler {

    public static final List<URI> DIDDOCUMENT_CONTEXTS = List.of(
            DIDContexts.JSONLD_CONTEXT_W3_NS_DID_V1,
            DIDContexts.JSONLD_CONTEXT_W3_NS_DID_V1_1
    );

    private static final URI RELATIVE_ID_INITIALKEY = URI.create("#initialKey");

    private static final Logger log = LoggerFactory.getLogger(DidDocUnAssembler.class);

    public static String unassembleBtcr2InitialKey(DIDDocument didDocument) {

        String unassembledBtcr2InitialKey = null;

        try {

            if (didDocument == null) return null;

            VerificationMethod verificationMethodInitialKey = findVerificationMethodInitialKey(didDocument);
            if (verificationMethodInitialKey == null) return null;

            if (!"Multikey".equals(verificationMethodInitialKey.getType())) {
                if (log.isWarnEnabled()) log.warn("Unexpected type for '#initialKey' verification method " + verificationMethodInitialKey.getId() + ": " + verificationMethodInitialKey.getType());
                return null;
            }

            unassembledBtcr2InitialKey = verificationMethodInitialKey.getPublicKeyMultibase();
            return unassembledBtcr2InitialKey;
        } finally {

            if (log.isDebugEnabled()) log.debug("Unassembled btcr2Initialkey: " + unassembledBtcr2InitialKey);
        }
    }

    public static Map<String, Object> unassembleDIDDocumentContent(DIDDocument didDocument) {

        if (didDocument == null) return null;

        Map<String, Object> unassembledDIDDocumentContent = new TreeMap<>(didDocument.toMap());

        String id = didDocument.getId() == null ? null : didDocument.getId().toString();
        unassembledDIDDocumentContent.remove("id");

        List<String> unassembledContexts = didDocument.getContexts() == null ? null : didDocument.getContexts()
                .stream()
                .filter(x -> !removeContext(x))
                .map(x -> x == null ? null : x.toString())
                .collect(Collectors.toList());
        List<Map<String, Object>> unassembledVerificationMethods = didDocument.getVerificationMethods() == null ? null : didDocument.getVerificationMethods()
                .stream()
                .filter(x -> !removeVerificationMethod(id, x))
                .map(x -> x == null ? null : x.toMap())
                .collect(Collectors.toList());
        List<Object> unassembledAuthentications = didDocument.getAuthenticationVerificationMethods() == null ? null : didDocument.getAuthenticationVerificationMethods()
                .stream()
                .filter(x -> !removeVerificationRelationship(id, x))
                .collect(Collectors.toList());
        List<Object> unassembledAssertionMethods = didDocument.getAssertionMethodVerificationMethods() == null ? null : didDocument.getAssertionMethodVerificationMethods()
                .stream()
                .filter(x -> !removeVerificationRelationship(id, x))
                .collect(Collectors.toList());
        List<Object> unassembledCapabilityInvocations = didDocument.getCapabilityInvocationVerificationMethods() == null ? null : didDocument.getCapabilityInvocationVerificationMethods()
                .stream()
                .filter(x -> !removeVerificationRelationship(id, x))
                .collect(Collectors.toList());
        List<Object> unassembledCapabilityDelegations = didDocument.getCapabilityDelegationVerificationMethods() == null ? null : didDocument.getCapabilityDelegationVerificationMethods()
                .stream()
                .filter(x -> !removeVerificationRelationship(id, x))
                .collect(Collectors.toList());

        if (log.isDebugEnabled()) log.debug("Unassembled '@context': " + unassembledContexts);
        if (log.isDebugEnabled()) log.debug("Unassembled 'verificationMethod': " + unassembledVerificationMethods);
        if (log.isDebugEnabled()) log.debug("Unassembled 'authentication': " + unassembledAuthentications);
        if (log.isDebugEnabled()) log.debug("Unassembled ' assertionMethod': " + unassembledAssertionMethods);
        if (log.isDebugEnabled()) log.debug("Unassembled ' capabilityInvocation': " + unassembledCapabilityInvocations);
        if (log.isDebugEnabled()) log.debug("Unassembled ' capabilityDelegation': " + unassembledCapabilityDelegations);

        if (unassembledContexts != null && ! unassembledContexts.isEmpty()) {
            unassembledDIDDocumentContent.put("@context", unassembledContexts);
        } else {
            unassembledDIDDocumentContent.remove("@context");
        }
        if (unassembledVerificationMethods != null && ! unassembledVerificationMethods.isEmpty()) {
            unassembledDIDDocumentContent.put("verificationMethod", unassembledVerificationMethods);
        } else {
            unassembledDIDDocumentContent.remove("verificationMethod");
        }
        if (unassembledAuthentications != null && ! unassembledAuthentications.isEmpty()) {
            unassembledDIDDocumentContent.put("authentication", unassembledAuthentications);
        } else {
            unassembledDIDDocumentContent.remove("authentication");
        }
        if (unassembledAssertionMethods != null && ! unassembledAssertionMethods.isEmpty()) {
            unassembledDIDDocumentContent.put("assertionMethod", unassembledAssertionMethods);
        } else {
            unassembledDIDDocumentContent.remove("assertionMethod");
        }
        if (unassembledCapabilityInvocations != null && ! unassembledCapabilityInvocations.isEmpty()) {
            unassembledDIDDocumentContent.put("capabilityInvocation", unassembledCapabilityInvocations);
        } else {
            unassembledDIDDocumentContent.remove("capabilityInvocation");
        }
        if (unassembledCapabilityDelegations != null && ! unassembledCapabilityDelegations.isEmpty()) {
            unassembledDIDDocumentContent.put("capabilityDelegation", unassembledCapabilityDelegations);
        } else {
            unassembledDIDDocumentContent.remove("capabilityDelegation");
        }

        if (unassembledDIDDocumentContent.isEmpty()) unassembledDIDDocumentContent = null;

        if (log.isDebugEnabled()) log.debug("Unassembled DID document content: " + unassembledDIDDocumentContent);
        return unassembledDIDDocumentContent;
    }

    private static boolean removeContext(URI context) {

        boolean remove = context != null && DIDDOCUMENT_CONTEXTS.contains(context);

        if (log.isDebugEnabled()) log.debug("Remove '@context' " + context + ": " + remove);
        return remove;
    }

    private static boolean removeVerificationMethod(String id, VerificationMethod verificationMethod) {

        URI absoluteIdVerkey = id == null ? null : URI.create(id + RELATIVE_ID_INITIALKEY);

        boolean remove;
        if (verificationMethod == null || verificationMethod.getId() == null)
            remove = false;
        else {
            URI verificationMethodId = verificationMethod.getId();
            remove = verificationMethodId.equals(RELATIVE_ID_INITIALKEY) || verificationMethodId.equals(absoluteIdVerkey);
        }

        if (log.isDebugEnabled()) log.debug("Remove 'verificationMethod' " + verificationMethod + " for id " + id + ": " + remove);
        return remove;
    }

    private static boolean removeVerificationRelationship(String id, Object authentication) {

        URI absoluteIdVerkey = id == null ? null : URI.create(id + RELATIVE_ID_INITIALKEY);

        boolean remove;
        if (authentication == null)
            remove = false;
        else {
            URI authenticationId = URI.create((String) authentication);
            remove = authenticationId.equals(RELATIVE_ID_INITIALKEY) || authenticationId.equals(absoluteIdVerkey);
        }

        if (log.isDebugEnabled()) log.debug("Remove 'authentication' " + authentication + " (" + (authentication == null ? null : authentication.getClass().getSimpleName()) + ") for id " + id + ": " + remove);
        return remove;
    }

    /*
     * Helper methods
     */

    private static VerificationMethod findVerificationMethodInitialKey(DIDDocument didDocument) {

        if (didDocument.getVerificationMethods() == null) return null;

        URI absoluteIdVerkey = didDocument.getId() == null ? null : URI.create(didDocument.getId().toString() + RELATIVE_ID_INITIALKEY);

        VerificationMethod verificationMethodInitialkey = null;
        for (VerificationMethod verificationMethod : didDocument.getVerificationMethods()) {
            if (verificationMethod == null || verificationMethod.getId() == null) continue;
            if (verificationMethod.getId().equals(RELATIVE_ID_INITIALKEY) || verificationMethod.getId().equals(absoluteIdVerkey)) {
                verificationMethodInitialkey = verificationMethod;
                break;
            }
        }

        if (log.isDebugEnabled()) log.debug("Found '#initialKey' verification method: " + verificationMethodInitialkey);
        return verificationMethodInitialkey;
    }
}

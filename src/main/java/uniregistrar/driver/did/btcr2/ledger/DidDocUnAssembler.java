package uniregistrar.driver.did.btcr2.ledger;

import com.apicatalog.jsonld.lang.Keywords;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.DIDDocumentV1_1;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.jsonld.DIDContexts;
import foundation.identity.did.jsonld.DIDKeywords;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDKeywords;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import fr.acinq.secp256k1.Hex;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.util.MultiCodecUtil;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DidDocUnAssembler {

    public static final URI JSONLD_CONTEXT_BTCR2_V1 = URI.create("https://btcr2.dev/context/v1");

    public static final List<URI> DIDDOCUMENT_CONTEXTS = List.of(
            DIDContexts.JSONLD_CONTEXT_W3_NS_DID_V1,
            DIDContexts.JSONLD_CONTEXT_W3_NS_DID_V1_1,
            JSONLD_CONTEXT_BTCR2_V1
    );

    private static final URI GENESIS_DID = URI.create("did:btcr2:_");
    private static final URI GENESIS_ID_VERIFICATIONMETHOD = URI.create("#initialKey");

    private static final Logger log = LoggerFactory.getLogger(DidDocUnAssembler.class);

    public static byte[] unassembleInitialKey(DIDDocument didDocument) {

        if (didDocument == null) return null;

        JsonLDObject verificationMethodInitialKeyJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didDocument, GENESIS_ID_VERIFICATIONMETHOD, null);
        VerificationMethod verificationMethodInitialKey = verificationMethodInitialKeyJsonLDObject == null ? null : VerificationMethod.fromJsonLDObject(verificationMethodInitialKeyJsonLDObject);
        if (verificationMethodInitialKey == null) return null;

        if (! "Multikey".equals(verificationMethodInitialKey.getType())) {
            if (log.isWarnEnabled()) log.warn("Unexpected type for '#initialKey' verification method " + verificationMethodInitialKey.getId() + ": " + verificationMethodInitialKey.getType());
            return null;
        }

        String unassembledInitialKeyString = verificationMethodInitialKey.getPublicKeyMultibase();
        byte[] unassembledInitialKey = MultiCodecUtil.removeMulticodec(Multibase.decode(unassembledInitialKeyString), MultiCodecUtil.MULTICODEC_SECP256K1_PUB);

        // done

        if (log.isDebugEnabled()) log.debug("unassembledInitialKey: {}", Hex.encode(unassembledInitialKey));
        return unassembledInitialKey;
    }

    public static DIDDocumentV1_1 unassembleGenesisDocument(DIDDocument didDocument) {

        if (didDocument == null) return null;

        DIDDocument testDidDocument = DIDDocument.fromJson(didDocument.toJson());

        List<String> contexts = JsonLDUtils.jsonLdGetStringList(testDidDocument.getJsonObject(), Keywords.CONTEXT);
        List<String> testContexts = contexts == null ? null : new ArrayList<>(contexts);
        if (testContexts != null) {
            testContexts.removeIf(DidDocUnAssembler::removeContext);
            if (testContexts.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, Keywords.CONTEXT);
        }
        List<Object> verificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        List<Object> testVerificationMethods = contexts == null ? null : new ArrayList<>(verificationMethods);
        if (testVerificationMethods != null) {
            testVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        }
        List<Object> authenticationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_AUTHENTICATION);
        List<Object> testAuthenticationVerificationMethods = authenticationVerificationMethods == null ? null : new ArrayList<>(authenticationVerificationMethods);
        if (testAuthenticationVerificationMethods != null) {
            testAuthenticationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testAuthenticationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_AUTHENTICATION);
        }
        List<Object> assertionMethodVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        List<Object> testAssertionMethodVerificationMethods = assertionMethodVerificationMethods == null ? null : new ArrayList<>(assertionMethodVerificationMethods);
        if (testAssertionMethodVerificationMethods != null) {
            testAssertionMethodVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testAssertionMethodVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        }
        List<Object> capabilityInvocationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
        List<Object> testCapabilityInvocationVerificationMethods = capabilityInvocationVerificationMethods == null ? null : new ArrayList<>(capabilityInvocationVerificationMethods);
        if (testCapabilityInvocationVerificationMethods != null) {
            testCapabilityInvocationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testCapabilityInvocationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
        }
        List<Object> capabilityDelegationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
        List<Object> testCapabilityDelegationVerificationMethods = capabilityDelegationVerificationMethods == null ? null : new ArrayList<>(capabilityDelegationVerificationMethods);
        if (testCapabilityDelegationVerificationMethods != null) {
            testCapabilityDelegationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testCapabilityDelegationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
        }

        if (log.isDebugEnabled()) log.debug("testDidDocument: " + testDidDocument);
        if (testDidDocument.getJsonObject().isEmpty()) return null;

        DIDDocumentV1_1 unassembledGenesisDocument = DIDDocumentV1_1.builder().base(didDocument).defaultContexts(false).id(GENESIS_DID).build();
        if (! unassembledGenesisDocument.getContexts().contains(JSONLD_CONTEXT_BTCR2_V1)) {
            JsonLDUtils.jsonLdAdd(unassembledGenesisDocument, Keywords.CONTEXT, JsonLDUtils.uriToString(JSONLD_CONTEXT_BTCR2_V1));
        }
        if (log.isDebugEnabled()) log.debug("unassembledGenesisDocument: " + unassembledGenesisDocument);

        return unassembledGenesisDocument;
    }

    private static boolean removeContext(String context) {
        return DIDDOCUMENT_CONTEXTS.contains(URI.create(context));
    }

    private static boolean removeVerificationMethod(Object verificationMethod) {
        if (verificationMethod instanceof String verificationMethodString) {
            return GENESIS_ID_VERIFICATIONMETHOD.toString().equals(verificationMethodString);
        } else if (verificationMethod instanceof Map<?, ?> verificationMethodObject) {
            return GENESIS_ID_VERIFICATIONMETHOD.toString().equals(verificationMethodObject.get(JsonLDKeywords.JSONLD_TERM_ID));
        }
        return false;
    }
}

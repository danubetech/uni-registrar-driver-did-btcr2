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
import uniregistrar.driver.did.btcr2.util.MulticodecUtil;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class DidDocUnAssembler {

    public static final List<URI> DIDDOCUMENT_CONTEXTS = List.of(
            DIDContexts.JSONLD_CONTEXT_W3_NS_DID_V1_1,
            URI.create("https://btcr2.dev/context/v1")
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
        byte[] unassembledInitialKey = MulticodecUtil.removeMulticodec(Multibase.decode(unassembledInitialKeyString), MulticodecUtil.MULTICODEC_SECP256K1_PUB);

        // done

        if (log.isDebugEnabled()) log.debug("unassembledInitialKey: {}", Hex.encode(unassembledInitialKey));
        return unassembledInitialKey;
    }

    public static DIDDocument unassembleGenesisDocument(DIDDocument didDocument) {

        if (didDocument == null) return null;

        DIDDocument testDidDocument = DIDDocument.fromJson(didDocument.toJson());

        List<String> contexts = JsonLDUtils.jsonLdGetStringList(testDidDocument.getJsonObject(), Keywords.CONTEXT);
        if (contexts != null) {
            contexts.removeIf(DidDocUnAssembler::removeContext);
            if (contexts.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, Keywords.CONTEXT);
        }
        List<Object> verificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        if (verificationMethods != null) {
            verificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (verificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        }
        List<Object> authenticationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_AUTHENTICATION);
        if (authenticationVerificationMethods != null) {
            authenticationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (authenticationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_AUTHENTICATION);
        }
        List<Object> assertionMethodVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        if (assertionMethodVerificationMethods != null) {
            assertionMethodVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (assertionMethodVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        }
        List<Object> capabilityInvocationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
        if (capabilityInvocationVerificationMethods != null) {
            capabilityInvocationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (capabilityInvocationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
        }
        List<Object> capabilityDelegationVerificationMethods = JsonLDUtils.jsonLdGetJsonArray(testDidDocument.getJsonObject(), DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
        if (capabilityDelegationVerificationMethods != null) {
            capabilityDelegationVerificationMethods.removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (capabilityDelegationVerificationMethods.isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
        }

        if (log.isDebugEnabled()) log.debug("testDidDocument: " + testDidDocument);
        if (testDidDocument.getJsonObject().isEmpty()) return null;

        DIDDocumentV1_1 genesisDocument = DIDDocumentV1_1.builder().base(didDocument).defaultContexts(false).contexts(DIDDOCUMENT_CONTEXTS).id(GENESIS_DID).build();
        if (log.isDebugEnabled()) log.debug("genesisDocument: " + genesisDocument);

        return genesisDocument;
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

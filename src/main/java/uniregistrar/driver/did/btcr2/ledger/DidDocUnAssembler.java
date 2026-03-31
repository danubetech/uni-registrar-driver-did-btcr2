package uniregistrar.driver.did.btcr2.ledger;

import com.apicatalog.jsonld.lang.Keywords;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.jsonld.DIDContexts;
import foundation.identity.did.jsonld.DIDKeywords;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import fr.acinq.secp256k1.Hex;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.driver.did.btcr2.util.MulticodecUtil;

import java.net.URI;
import java.util.List;

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

        if (testDidDocument.getContexts() != null) {
            testDidDocument.getContexts().removeIf(DidDocUnAssembler::removeContext);
            if (testDidDocument.getContexts().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, Keywords.CONTEXT);
        }
        if (testDidDocument.getVerificationMethods() != null) {
            testDidDocument.getVerificationMethods().removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testDidDocument.getVerificationMethods().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
        }
        if (testDidDocument.getAuthenticationVerificationMethods() != null) {
            testDidDocument.getAuthenticationVerificationMethods().removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testDidDocument.getAuthenticationVerificationMethods().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_AUTHENTICATION);
        }
        if (testDidDocument.getAssertionMethodVerificationMethods() != null) {
            testDidDocument.getAssertionMethodVerificationMethods().removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testDidDocument.getAssertionMethodVerificationMethods().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        }
        if (testDidDocument.getCapabilityInvocationVerificationMethods() != null) {
            testDidDocument.getCapabilityInvocationVerificationMethods().removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testDidDocument.getCapabilityInvocationVerificationMethods().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYINVOCATION);
        }
        if (testDidDocument.getCapabilityDelegationVerificationMethods() != null) {
            testDidDocument.getCapabilityDelegationVerificationMethods().removeIf(DidDocUnAssembler::removeVerificationMethod);
            if (testDidDocument.getCapabilityDelegationVerificationMethods().isEmpty()) JsonLDUtils.jsonLdRemove(testDidDocument, DIDKeywords.JSONLD_TERM_CAPABILITYDELEGATION);
        }

        if (log.isDebugEnabled()) log.debug("Test DID document: " + testDidDocument);
        if (testDidDocument.getJsonObject().isEmpty()) return null;

        DIDDocument genesisDocument = DIDDocument.fromJson(didDocument.toJson().replace(didDocument.getId().toString(), GENESIS_DID.toString()));
        if (log.isDebugEnabled()) log.debug("Genesis document: " + genesisDocument);

        return genesisDocument;
    }

    private static boolean removeContext(URI context) {
        return DIDDOCUMENT_CONTEXTS.contains(context);
    }

    private static boolean removeVerificationMethod(VerificationMethod verificationMethod) {
        return GENESIS_ID_VERIFICATIONMETHOD.equals(verificationMethod.getId());
    }

    private static boolean removeVerificationMethod(Object verificationRelationship) {
        return ((verificationRelationship instanceof String) && GENESIS_ID_VERIFICATIONMETHOD.equals(URI.create((String) verificationRelationship)));
    }
}

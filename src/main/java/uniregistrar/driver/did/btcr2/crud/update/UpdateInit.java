package uniregistrar.driver.did.btcr2.crud.update;

import com.danubetech.btc.connection.BitcoinConnection;
import com.danubetech.dataintegrity.jsonld.DataIntegrityKeywords;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.did.validation.Validation;
import foundation.identity.jsonld.JsonLDDereferencer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import jakarta.json.JsonPatch;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Coin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniregistrar.RegistrationException;
import uniregistrar.driver.did.btcr2.algorithms.JSONDocumentHashing;
import uniregistrar.driver.did.btcr2.data.jsonld.BTCR2Update;
import uniregistrar.driver.did.btcr2.ipfs.IPFSConnection;
import uniregistrar.driver.did.btcr2.util.JSONPatchUtil;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/*
 * Update
 * See https://dcdpr.github.io/did-btcr2/operations/update.html
 */

public class UpdateInit {

    private static final String BTCR2_UNSIGNED_UPDATE_TEMPLATE =
            """
                {
                  "@context": [
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
                  ],
                  "patch": {{array-of-patches}},
                  "sourceHash": "{{source-hash}}",
                  "targetHash": "{{target-hash}}",
                  "targetVersionId": {{target-version-id}}
                }
            """;

    private static final String DATA_INTEGRITY_TEMPLATE =
            """
                {
                  "@context": [
                    "https://btcr2.dev/context/v1",
                    "https://w3id.org/json-ld-patch/v1",
                    "https://w3id.org/zcap/v1",
                    "https://w3id.org/security/data-integrity/v2"
                  ],
                  "type": "DataIntegrityProof",
                  "cryptosuite": "bip340-jcs-2025",
                  "verificationMethod": "{{ verification-method }}",
                  "proofPurpose": "capabilityInvocation",
                  "capability": "{{ capability }}",
                  "capabilityAction": "Write"
                }
            """;

    private static final Coin BITCOIN_FEE = Coin.valueOf(100);

    private static final Logger log = LoggerFactory.getLogger(UpdateInit.class);

    private IPFSConnection ipfsConnection;

    public UpdateInit(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }

    public UpdateInitResult update(BitcoinConnection bitcoinConnection, DIDDocument didSourceDocument, Integer targetVersionId, JsonPatch jsonPatches, URI verificationMethodId, Map<String, Object> didDocumentMetadata) throws RegistrationException {

        /*
         * Construct BTCR2 Unsigned Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-unsigned-update
         */

        // Apply all JSON patches in jsonPatches to didSourceDocument to create didTargetDocument.

        DIDDocument didTargetDocument = didSourceDocument;
        didTargetDocument = JSONPatchUtil.apply(didTargetDocument, jsonPatches);
        if (log.isDebugEnabled()) log.debug("didTargetDocument: " + didTargetDocument);

        // didTargetDocument MUST be conformant to DID Core v1.1

        try {
            Validation.validate(didTargetDocument);
        } catch (IllegalStateException ex) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "Invalid didTargetDocument: " + ex.getMessage(), ex);
        }

        // An INVALID_DID_UPDATE error MUST be raised if didTargetDocument.id is not equal to didSourceDocument.id.

        if (! didTargetDocument.getId().equals(didSourceDocument.getId())) {
            throw new RegistrationException(RegistrationException.ERROR_INVALID_DID_DOCUMENT, "didTargetDocument.id " + didTargetDocument.getId() + " does not match didSourceDocument.id " + didSourceDocument.getId());
        }

        // Fill the BTCR2 Unsigned Update (data structure) template below with the required template variables.

        String updateString = BTCR2_UNSIGNED_UPDATE_TEMPLATE
                .replace("{{array-of-patches}}", jsonPatches.toJsonArray().toString())
                .replace("{{source-hash}}", Base64.getUrlEncoder().withoutPadding().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didSourceDocument)))
                .replace("{{target-hash}}", Base64.getUrlEncoder().withoutPadding().encodeToString(JSONDocumentHashing.jsonDocumentHashing(didTargetDocument)))
                .replace("{{target-version-id}}", targetVersionId.toString());
        if (log.isDebugEnabled()) log.debug("updateString: " + updateString);

        // Let update be the result of parsing the rendered template as JSON.

        BTCR2Update btcr2Update = BTCR2Update.fromJson(updateString);
        if (log.isDebugEnabled()) log.debug("btcr2Update: " + btcr2Update);

        /*
         * Construct BTCR2 Signed Update
         * See https://dcdpr.github.io/did-btcr2/operations/update.html#construct-btcr2-signed-update
         */

        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.verificationMethod Set does not contain an id matching verificationMethodId.
        // An INVALID_DID_UPDATE error MUST be raised if the didSourceDocument.capabilityInvocation Set does not contain verificationMethodId.

        JsonLDObject verificationMethodJsonLDObject = JsonLDDereferencer.findByIdInJsonLdObject(didSourceDocument, verificationMethodId, didSourceDocument.getId());
        VerificationMethod verificationMethod = verificationMethodJsonLDObject == null ? null : VerificationMethod.fromJsonObject(verificationMethodJsonLDObject.getJsonObject());
        if (verificationMethod == null || ! didSourceDocument.getVerificationMethods().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.verificationMethod does not contain " + verificationMethodId);
        }

        if (! didSourceDocument.getCapabilityInvocationVerificationMethodsDereferenced().contains(verificationMethod)) {
            throw new RegistrationException("INVALID_DID_UPDATE", "didSourceDocument.capabilityInvocation does not contain " + verificationMethodId);
        }

        // Create cryptosuite as a BIP340 Cryptosuite [BIP340-Cryptosuite] instance with privateKey and "bip340-jcs-2025" cryptosuite.

        DataIntegrityProofLdSigner cryptosuite = new DataIntegrityProofLdSigner();
        cryptosuite.setCryptosuite("bip340-jcs-2025");

        // Fill the Data Integrity [VC-DATA-INTEGRITY] template below with the required template variables.

        URI cryptosuiteVerificationMethod = verificationMethod.getId();
        if (! cryptosuiteVerificationMethod.isAbsolute()) cryptosuiteVerificationMethod = URI.create(didSourceDocument.getId() + cryptosuiteVerificationMethod.toString());
        URI cryptosuiteCapability = URI.create("urn:zcap:root:" + URLEncoder.encode(didSourceDocument.getId().toString(), StandardCharsets.UTF_8));

        cryptosuite.setVerificationMethod(cryptosuiteVerificationMethod);
        cryptosuite.setProofPurpose("capabilityInvocation");
        cryptosuite.setCapability(cryptosuiteCapability);
        cryptosuite.setCapabilityAction("Write");

        // Pass update and proofConfig to the cryptosuite.createProof method and set
        // update.proof to the resulting Data Integrity Proof (data structure).

        byte[] updateSignPayload;

        try {

            final AtomicReference<byte[]> reference = new AtomicReference<>();

            JsonLDUtils.jsonLdRemove(btcr2Update, DataIntegrityKeywords.JSONLD_TERM_PROOF);

            cryptosuite.setSigner(new ByteSigner(JWSAlgorithm.ES256KS) {
                @Override
                protected byte[] sign(byte[] bytes) {
                    if (log.isDebugEnabled()) log.debug("Signing bytes {}", Hex.encodeHexString(bytes));
                    reference.set(bytes);
                    return new byte[0];
                }
            });
            cryptosuite.sign(btcr2Update, false, false);

            updateSignPayload = reference.get();
        } catch (IOException | GeneralSecurityException | JsonLDException ex) {
            throw new RegistrationException("Cannot sign the BTCR2 Update: " + ex.getMessage(), ex);
        }

        // result

        UpdateInitResult updateInitResult = new UpdateInitResult(verificationMethodId, btcr2Update, updateSignPayload);
        if (log.isDebugEnabled()) log.debug("Update: " + updateInitResult);
        return updateInitResult;
    }

    /*
     * Getters and setters
     */

    public IPFSConnection getIpfsConnection() {
        return ipfsConnection;
    }

    public void setIpfsConnection(IPFSConnection ipfsConnection) {
        this.ipfsConnection = ipfsConnection;
    }
}

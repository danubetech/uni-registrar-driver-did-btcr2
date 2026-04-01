package uniregistrar.driver.did.btcr2.util;

import foundation.identity.did.DIDDocument;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonPatch;

import java.io.StringWriter;

public class JSONPatchUtil {

    public static DIDDocument apply(DIDDocument didDocument, JsonPatch jsonPatches) {
        JsonObject didDocumentObject = Json.createObjectBuilder(didDocument.toMap()).build();
        JsonObject patchedDidDocumentObject = jsonPatches.apply(didDocumentObject);
        StringWriter stringWriter = new StringWriter();
        Json.createWriter(stringWriter).write(patchedDidDocumentObject);
        return DIDDocument.fromJson(stringWriter.toString());
    }
}

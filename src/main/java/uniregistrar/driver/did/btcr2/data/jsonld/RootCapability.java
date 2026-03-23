package uniregistrar.driver.did.btcr2.data.jsonld;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.fasterxml.jackson.annotation.JsonCreator;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

import java.io.Reader;
import java.net.URI;
import java.util.Map;

public class RootCapability extends JsonLDObject {

    public static final URI[] DEFAULT_JSONLD_CONTEXTS = { URI.create("https://w3id.org/zcap/v1") };
    public static final String[] DEFAULT_JSONLD_TYPES = { };
    public static final String DEFAULT_JSONLD_PREDICATE = null;
    public static final DocumentLoader DEFAULT_DOCUMENT_LOADER = JsonLDObject.DEFAULT_DOCUMENT_LOADER;

    @JsonCreator
    public RootCapability() {
        super();
    }

    protected RootCapability(Map<String, Object> jsonObject) {
        super(jsonObject);
    }

    /*
     * Factory methods
     */

    public static class Builder<B extends Builder<B>> extends JsonLDObject.Builder<B> {

        private URI controller;
        private URI invocationTarget;

        public Builder(RootCapability jsonLDObject) {
            super(jsonLDObject);
            this.forceContextsArray(true);
            this.forceTypesArray(true);
            this.defaultContexts(true);
            this.defaultTypes(false);
        }

        @Override
        public RootCapability build() {

            super.build();

            // add JSON-LD properties

            if (this.controller != null) {
                JsonLDUtils.jsonLdAdd(this.jsonLdObject, "controller", JsonLDUtils.uriToString(this.controller));
                JsonLDUtils.jsonLdAdd(this.jsonLdObject, "invocationTarget", JsonLDUtils.uriToString(this.invocationTarget));
            }

            return (RootCapability) this.jsonLdObject;
        }

        public B controller(URI controller) {
            this.controller = controller;
            return (B) this;
        }

        public B invocationTarget(URI invocationTarget) {
            this.invocationTarget = invocationTarget;
            return (B) this;
        }
    }

    public static Builder<? extends Builder<?>> builder() {
        return new Builder<>(new RootCapability());
    }

    public static RootCapability fromJsonObject(Map<String, Object> jsonObject) {
        return new RootCapability(jsonObject);
    }

    public static RootCapability fromJsonLDObject(JsonLDObject jsonLDObject) { return fromJsonObject(jsonLDObject.getJsonObject()); }

    public static RootCapability fromJson(Reader reader) {
        return new RootCapability(readJson(reader));
    }

    public static RootCapability fromJson(String json) {
        return new RootCapability(readJson(json));
    }

    public static RootCapability fromMap(Map<String, Object> map) {
        return new RootCapability(map);
    }

    /*
     * Getters
     */

    public URI getController() {
        String jsonString = JsonLDUtils.jsonLdGetString(this.getJsonObject(), "controller");
        return JsonLDUtils.stringToUri(jsonString);
    }

    public URI getInvocationTarget() {
        String jsonString = JsonLDUtils.jsonLdGetString(this.getJsonObject(), "invocationTarget");
        return JsonLDUtils.stringToUri(jsonString);
    }
}

package common.transport.SSU;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import java.io.InvalidObjectException;
import java.security.SecureRandom;

public class SSUMessage implements JSONSerializable {
    /**
     * Types of messages {@code SESSIONREQUEST, SESSIONCREATED, SESSIONCONFIRMED, SESSIONDESTROYED, DATA, ACK}
     */
    public enum SSUMessageTypes {
        SESSIONREQUEST,
        SESSIONCREATED,
        SESSIONCONFIRMED,
        SESSIONDESTROYED,
        DATA,
        ACK,
    }

    /**
     * Source of randomness
     */
    protected SecureRandom random = new SecureRandom();
    /**
     * Type of message
     */
    protected SSUMessageTypes type;

    /**
     * Create message with type
     * @param type enum of type
     */
    protected SSUMessage(SSUMessageTypes type) {
        this.type = type;
    }

    /**
     * Create new SSU Message from JSON
     * @param json json to deserialize
     * @throws InvalidObjectException if json is invalid
     */
    protected SSUMessage(JSONObject json) throws InvalidObjectException{
        deserialize(json);
    }
    /**
     * Returns type of message Type of message Enum {@code SESSIONREQUEST, SESSIONCREATED, SESSIONCONFIRMED, SESSIONDESTROYED, DATA, ACK}
     */
    public SSUMessageTypes getType() {
        return type;
    }

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        if (!(jsonType instanceof JSONObject))
            throw new InvalidObjectException("Must be JSONObject");

        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"type"});
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = new JSONObject();
        json.put("type", type.ordinal());
        return json;
    }
}

package common.transport;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import java.io.InvalidObjectException;

public class SSUMessage implements JSONSerializable {
    public enum SSUMessageTypes {
        SESSIONREQUEST,
        SESSIONCREATED,
        SESSIONCONFIRMED,
        DATA,
        ACK,
        SESSIONTEARDOWN,
    }

    protected SSUMessageTypes type;

    protected SSUMessage(SSUMessageTypes type) {
        this.type = type;
    }

    protected SSUMessage(JSONObject json) throws InvalidObjectException{
        deserialize(json);
    }
    /**
     * Returns type of message Type of message Enum {@code SESSIONREQUEST, SESSIONCREATED, SESSIONCONFIRMED, SESSIONDESTROYED, DATA, ACK}
     * @return
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

package common.transport.SSU;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import org.bouncycastle.util.encoders.Base64;

import java.io.InvalidObjectException;

public class ACK extends SSUMessage{
    /**
     * Nonce of message to ack
     */
    private byte[] nonce;

    /**
     * Create an ACK message
     * @param nonce Nonce of message to ACK
     */
    public ACK(byte[] nonce) {
        super(SSUMessageTypes.ACK);

    }

    public ACK(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("nonce", Base64.toBase64String(nonce));
        return json;
    }

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        super.deserialize(jsonType);

        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"nonce"});
        //super class handles deserialization
        nonce = Base64.decode(json.getString("nonce"));
    }
}

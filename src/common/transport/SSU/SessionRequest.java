package common.transport.SSU;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import org.bouncycastle.util.encoders.Base64;

import java.io.InvalidObjectException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static common.transport.SSU.SSUMessage.SSUMessageTypes.SESSIONREQUEST;

public class SessionRequest extends SSUMessage {
    /**
     * Public Shared data for DH exchange
     */
    private PublicKey DHPub;
    //todo add ip address?

    /**
     * Create a new Session request
     * @param DHPub DH public key of session request
     */
    public SessionRequest(PublicKey DHPub) {
        super(SESSIONREQUEST);
        this.DHPub = DHPub;
    }

    /**
     * Create a new Session request from json
     * @param json JSON to deserialize
     * @throws InvalidObjectException Throws if invalid
     */
    public SessionRequest(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }


    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        JSONObject json = super.toJSONType();
        json.checkValidity(new String[] {"DHPub"});

        byte[] DHPubBytes = Base64.decode(json.getString("DHPub"));

        //attempt to get public key
        try {
            DHPub = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(DHPubBytes));
        }
        catch (InvalidKeySpecException e) {throw new InvalidObjectException("Public Key is not valid");}
        catch (NoSuchAlgorithmException e) {throw new RuntimeException(e);} //should never hit case
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("DHPub", Base64.toBase64String(DHPub.getEncoded()));
        return json;
    }

    public PublicKey getDHPub() {
        return DHPub;
    }
}

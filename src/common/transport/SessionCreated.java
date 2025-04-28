package common.transport;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import java.io.InvalidObjectException;
import java.security.*;

public class SessionCreated extends SSUMessage {
    /**
     * Y - DHPub key to complete key exchange
     */
    private PublicKey DHPub;
    //todo add ip and port?
    /**
     * 16 byte IV for encryption
     */
    private byte[] IV;
    /**
     * 16 byte Nonce of message
     */
    private byte[] nonce;

    /**
     * Signature of all data
     */
    private byte[] signature;
    //todo add port + ip?

    public SessionCreated(PublicKey DHPub, PublicKey xDHPub, byte[] nonce, PrivateKey signingKey) {
        super(SSUMessageTypes.SESSIONCREATED);
        this.DHPub = DHPub;
        this.IV = new byte[16];

        //create signature
        try {
            //get signature ready
            Signature signing = Signature.getInstance("Ed25519");
            signing.initSign(signingKey);
            //sign this RouterInfo
            signing.update(xDHPub.getEncoded());
            signing.update(DHPub.getEncoded());
            signing.update(nonce);
            //todo add ip/routerinfo to bind to connection?
            signature = signing.sign();
            this.signature = signing.sign();
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e); //should never hit case
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Bad private key for SHA1withDSA" + e);
        }

        //encrypt signature with
    }

    public SessionCreated(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }
    /**
     * @param jsonType
     * @throws InvalidObjectException
     */
    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {

    }

    /**
     * @return
     */
    @Override
    public JSONObject toJSONType() {
        return null;
    }
}

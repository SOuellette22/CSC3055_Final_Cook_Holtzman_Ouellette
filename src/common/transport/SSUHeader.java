package common.transport;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InvalidObjectException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class SSUHeader implements JSONSerializable {
    /**
     * Type of message Enum {@code SESSIONREQUEST, SESSIONCREATED, SESSIONCONFIRMED, SESSIONDESTROYED, DATA, ACK}
     */
    private SSUMessageTypes type;
    /**
     * 16 byte Nonce for messages
     */
    private byte[] nonce;
    /**
     * 16 byte IV for encryption
     */
    private byte[] IV;
    private byte[] data;
    private SecureRandom random = new SecureRandom();



    public SSUHeader(SSUMessage message, SecretKey sessionKey, byte[] nonce) {
        if (message.getType() == SSUMessageTypes.SESSIONREQUEST)
            throw new IllegalArgumentException("Wrong constructor - need public key");

        this.nonce = nonce;
        this.type = message.getType();
        this.IV = new byte[16];
        random.nextBytes(IV);

        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmParams);

            //update aed with type and nonce
            aesCipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(type.ordinal()).array());
            aesCipher.updateAAD(nonce);

            //encrypt message
            data = aesCipher.doFinal(message.serialize().getBytes(StandardCharsets.UTF_8));

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    public SSUHeader(SSUMessage message, PublicKey keyShare, byte[] nonce) {
        if (!(message.getType() == SSUMessageTypes.SESSIONREQUEST || message.getType() == SSUMessageTypes.SESSIONRESPONSE))
            throw new IllegalArgumentException("Constructor only for session request");
    }
    SSUHeader(JSONObject json) throws InvalidObjectException {
        deserialize(json);
    }

    public SSUMessage getMessage(SecretKey sessionKey) throws InvalidObjectException {
        //attempt to decrypt message
        try {
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);

            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParams);

            //update aed with type and nonce
            aesCipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(type.ordinal()).array());
            aesCipher.updateAAD(nonce);

            //decrypt data
            byte[] decData = aesCipher.doFinal(data);
            //attempt to read json
            JSONObject json = JsonIO.readObject(new String(data, StandardCharsets.UTF_8));


        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //should never hit case
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e); //not 100% sure when these failure modes could arise
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key given " + e.getMessage());
        }
    }

    /**
     * @param jsonType
     * @throws InvalidObjectException
     */
    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        if (!(jsonType instanceof JSONObject))
            throw new InvalidObjectException("Must be JSONObject");

        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"type", "nonce", "IV", "encData"});

        type = SSUMessageTypes.values()[json.getInt("type")]; //get enum type based on ordinal
        nonce = Base64.decode("nonce");
        IV = Base64.decode("IV");

        data = Base64.decode(json.getString("data"));
    }


    @Override
    public JSONObject toJSONType() {
        JSONObject json = new JSONObject();
        json.put("type", type.ordinal());
        json.put("nonce", Base64.toBase64String(nonce));
        json.put("IV", Base64.toBase64String(IV));
        json.put("data", Base64.toBase64String(data));
        return json;
    }
}

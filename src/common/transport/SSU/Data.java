package common.transport.SSU;


import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InvalidObjectException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Data extends SSUMessage {
    /**
     * Encrypted data of message
     */
    private byte[] data;
    /**
     * Nonce of message
     */
    private byte[] nonce;
    /**
     * 16 bytes IV for encryption
     */
    private byte[] IV;
    /**
     * Response flag, true if message should be acked false otherwise
     */
    private Boolean response;

    /**
     * Create new data message
     * @param connectionID ID of this connection
     * @param data Data is payload of message
     * @param response flag for if message should be acked or not
     * @param nonce 16 byte nonce of message
     * @param sessionKey AES key for encryption
     */
    public Data(int connectionID, byte[] data, boolean response, byte[] nonce, SecretKey sessionKey) {
        super(SSUMessageTypes.DATA, connectionID);
        this.response = response;
        this.nonce = nonce;

        this.IV = new byte[16];
        random.nextBytes(this.IV);

        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmParams);

            aesCipher.updateAAD(nonce);
            aesCipher.updateAAD(new byte[] { (byte) (response ? 0x01 : 0x00) }); //put 1 if true else put 0
            //encrypt message
            this.data = aesCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    public Data(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }

    /**
     * Gets decrypted data in message
     * @param sessionKey AES key for decryption
     * @return Data in message
     */
    public byte[] getData(SecretKey sessionKey) {
        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParams);

            aesCipher.updateAAD(nonce);
            aesCipher.updateAAD(new byte[] { (byte) (response ? 0x01 : 0x00) }); //put 1 if true else put 0

            //get decrypted data
            return aesCipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    /**
     * Get response flag
     * @return True is message should be acked false otherwise
     */
    public boolean respond() {
        return response;
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        super.deserialize(jsonType);
        //JSONObject check handled by super class
        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"IV", "nonce", "response", "data"});

        IV = Base64.decode(json.getString("IV"));
        nonce = Base64.decode(json.getString("nonce"));
        response = json.getBoolean("response");
        data = Base64.decode(json.getString("data"));
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("IV", Base64.toBase64String(IV));
        json.put("nonce", Base64.toBase64String(nonce));
        json.put("response", response);
        json.put("data", Base64.toBase64String(data));
        return json;
    }
}

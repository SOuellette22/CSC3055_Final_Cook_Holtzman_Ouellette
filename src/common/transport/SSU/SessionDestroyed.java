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
import java.util.Arrays;

import static common.transport.SSU.SSUMessage.SSUMessageTypes.SESSIONDESTROYED;

public class SessionDestroyed extends SSUMessage {
    /**
     * 16 byte IV for encryption
     */
    private byte[] IV;
    /**
     * 16 byte Nonce of message
     */
    private byte[] nonce;
    /**
     * Encrypted Nonce
     */
    private byte[] encNonce;
    /**
     * Create session destroyed message
     * @param connectionID ID of this connection
     * @param nonce Nonce of message
     * @param sessionKey Session Key to encrypt Nonce
     */
    public SessionDestroyed(int connectionID, byte[] nonce, SecretKey sessionKey) {
        super(SESSIONDESTROYED, connectionID);
        this.nonce = nonce;
        this.IV = new byte[16];
        random.nextBytes(this.IV);

        //encrypt signature with the session key
        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmParams);

            //encrypt message
            encNonce = aesCipher.doFinal(nonce);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    public SessionDestroyed(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }

    /**
     * Verifies message of teardown request
     * @param sessionKey AES session key
     * @return true if message is valid false otherwise
     */
    public boolean verifyMessage(SecretKey sessionKey) {
        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParams);

            //get decrypted nonce  message
            byte[] decNonce = aesCipher.doFinal(nonce);
            //check if arrays still match
            return Arrays.equals(decNonce, nonce);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("IV", Base64.toBase64String(IV));
        json.put("nonce", Base64.toBase64String(nonce));
        json.put("encNonce", Base64.toBase64String(encNonce));
        return json;
    }

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        super.deserialize(jsonType);

        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"IV", "nonce", "encNonce"});
        //super class handles deserialization
        IV = Base64.decode(json.getString("IV"));
        nonce = Base64.decode(json.getString("nonce"));
        encNonce = Base64.decode(json.getString("encNonce"));
    }
}

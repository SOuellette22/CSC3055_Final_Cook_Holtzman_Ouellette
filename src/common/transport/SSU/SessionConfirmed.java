package common.transport.SSU;

import common.Logger;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InvalidObjectException;
import java.nio.ByteBuffer;
import java.security.*;

import static common.transport.SSU.SSUMessage.SSUMessageTypes.SESSIONCONFIRMED;

public class SessionConfirmed extends SSUMessage {
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

    /**
     * Create session confirmed message by signing then encrypting signature with session key
     * @param xDHPub X of DH Key share from SessionRequest
     * @param yDHPub Y of DH key share from SessionCreated
     * @param nonce 16 byte nonce of this message
     * @param signingKey Router's private key to sign message
     * @param sessionKey AES Session key created from shared secret
     */
    public SessionConfirmed(PublicKey xDHPub, PublicKey yDHPub, byte[] nonce, PrivateKey signingKey, SecretKey sessionKey) {
        super(SESSIONCONFIRMED);
        this.IV = new byte[16];
        random.nextBytes(this.IV);

        //create signature
        try {
            //get signature ready
            Signature signing = Signature.getInstance("Ed25519");
            signing.initSign(signingKey);
            //sign this critical session data
            signing.update(xDHPub.getEncoded()); //DH-key share X
            signing.update(yDHPub.getEncoded()); //DH-key share Y
            signing.update(nonce);
            //todo add ip/routerinfo to bind to connection?

            this.signature = signing.sign();
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e); //should never hit case
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Bad private key for Ed25519" + e);
        }
        //encrypt signature with the session key
        try {
            //create cipher
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);
            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmParams);

            //update aed with type and nonce and dh-pub
            aesCipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(type.ordinal()).array());
            aesCipher.updateAAD(nonce);

            //encrypt message
            signature = aesCipher.doFinal(signature);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new RuntimeException(e); //should not hit cases in prod
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key cannot create message" + e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Bad padding message might need to be decreased" + e);
        }
    }

    /**
     * Verify signature to confirm session first decrypt signature with session key from shared secret then verify signature
     * @param verificationKey ed25519 public verification key to verify signature
     * @param sessionKey AES key from shared secret for decryption
     * @param DHpubx X Key share infromation from SessionRequest
     * @param DHpuby Y Key Share infromation from SessionCreated
     * @return True if signature is valid false otherwise
     */
    public boolean verifySignature(PublicKey verificationKey, SecretKey sessionKey, PublicKey DHpubx, PublicKey DHpuby) {
        //decrypt signature
        try {
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);

            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParams);

            //update aed with type and nonce and dhpub
            aesCipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(type.ordinal()).array());
            aesCipher.updateAAD(nonce);

            //decrypt data
            byte[] decData = aesCipher.doFinal(signature);
            //verify signature

            //get signature ready
            Signature signing = Signature.getInstance("Ed25519");
            signing.initVerify(verificationKey);

            signing.update(DHpubx.getEncoded()); //Key from request message
            signing.update(DHpuby.getEncoded()); //Our key share
            signing.update(nonce);

            return signing.verify(decData);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //should never hit case
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e); //not 100% sure when these failure modes could arise
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Bad key given " + e.getMessage());
        } catch (SignatureException e) {
            Logger.getInstance().warn("Bad signature "  +e.getMessage());
            return false;
        }
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        super.deserialize(jsonType);
        //json obj check handled in super class
        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"IV", "nonce", "signature"});

        IV = Base64.decode(json.getString("IV"));
        nonce = Base64.decode(json.getString("nonce"));
        signature = Base64.decode(json.getString("signature"));
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("IV", Base64.toBase64String(IV));
        json.put("nonce", Base64.toBase64String(nonce));
        json.put("signature", Base64.toBase64String(signature));
        return json;
    }
}

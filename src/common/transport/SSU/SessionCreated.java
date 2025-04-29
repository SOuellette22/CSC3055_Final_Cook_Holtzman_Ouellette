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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static common.transport.SSU.SSUMessage.SSUMessageTypes.SESSIONCREATED;

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

    /**
     * Create SessionCreated mession
     * @param connectionID ID of this connection
     * @param yDHPub Our DH-key share Y
     * @param xDHPub Other parties DH-Key share X
     * @param nonce 16 byte nonce
     * @param signingKey Router's private key to sign message
     * @param sessionKey Session key created from shared secret after DH key share
     */
    public SessionCreated(int connectionID, PublicKey yDHPub, PublicKey xDHPub, byte[] nonce, byte[] IV, PrivateKey signingKey, SecretKey sessionKey) {
        super(SESSIONCREATED, connectionID);
        this.DHPub = yDHPub;
        this.IV = IV;
        //create signature
        try {
            //get signature ready
            Signature signing = Signature.getInstance("Ed25519");
            signing.initSign(signingKey);
            //sign this critical session data
            signing.update(xDHPub.getEncoded()); //Key from request message
            signing.update(DHPub.getEncoded()); //Our key share
            signing.update(nonce);
            //todo add ip/routerinfo to bind to connection?

            this.signature = signing.sign();
        } catch (NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException(e); //should never hit case
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Bad private key for SHA1withDSA" + e);
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
            aesCipher.updateAAD(DHPub.getEncoded());

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

    public SessionCreated(JSONObject json) throws InvalidObjectException {
        super(json);
        deserialize(json);
    }

    /**
     * Get DH key share - Y
     * @return DH secret exchange
     */
    public PublicKey getDHPub() {
        return DHPub;
    }

    /**
     * Verify signature by decrypting it then verifying signature
     * @param verificationKey Public key for Ed25519 signature verification
     * @param sessionKey AES session key computed from shared secret
     * @param DHpubx DHpub key share from x
     * @return True if verifies false otherwise
     */
    public boolean verifySignature(PublicKey verificationKey, SecretKey sessionKey, PublicKey DHpubx) {
        //decrypt signature
        try {
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, IV);

            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParams);

            //update aed with type and nonce and dhpub
            aesCipher.updateAAD(ByteBuffer.allocate(Integer.BYTES).putInt(type.ordinal()).array());
            aesCipher.updateAAD(nonce);
            aesCipher.updateAAD(DHPub.getEncoded());

            //decrypt data
            byte[] decData = aesCipher.doFinal(signature);
           //verify signature

            //get signature ready
            Signature signing = Signature.getInstance("Ed25519");
            signing.initVerify(verificationKey);

            signing.update(DHpubx.getEncoded()); //Key from request message
            signing.update(DHPub.getEncoded()); //Our key share
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

    @Override
    public void deserialize(JSONType jsonType) throws InvalidObjectException {
        super.deserialize(jsonType);
        //super class checks type
        JSONObject json = (JSONObject) jsonType;
        json.checkValidity(new String[] {"DHPub", "IV", "nonce", "signature"});
        //create public key from DHPub
        byte[] DHPubBytes = Base64.decode(json.getString("DHPub"));
        //attempt to get public key
        try {
            DHPub = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(DHPubBytes));
        }
        catch (InvalidKeySpecException e) {throw new InvalidObjectException("Public Key is not valid");}
        catch (NoSuchAlgorithmException e) {throw new RuntimeException(e);} //should never hit case

        IV = Base64.decode(json.getString("IV"));
        nonce = Base64.decode(json.getString("nonce"));
        signature = Base64.decode(json.getString("signature"));
    }

    @Override
    public JSONObject toJSONType() {
        JSONObject json = super.toJSONType();
        json.put("DHPub", Base64.toBase64String(DHPub.getEncoded()));
        json.put("IV", Base64.toBase64String(IV));
        json.put("nonce", Base64.toBase64String(nonce));
        json.put("signature", Base64.toBase64String(signature));
        return json;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getIV() {
        return IV;
    }
}

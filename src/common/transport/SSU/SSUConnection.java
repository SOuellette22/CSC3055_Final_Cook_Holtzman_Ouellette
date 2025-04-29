package common.transport.SSU;

import common.Logger;
import merrimackutil.util.NonceCache;
import org.bouncycastle.crypto.generators.SCrypt;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class SSUConnection {
    /**
     * MAX Size of datagram packets - this is hacky I just set it large in hopes we dont reach it
     */
    private final int MAX_SIZE = 4096;
    /**
     * Logger
     */
    private Logger log = Logger.getInstance();
    /**
     * Source of secure randomness
     */
    private SecureRandom random = new SecureRandom();
    /**
     * ID for this connection
     */
    private int connectionID;
    /**
     *
     */
    private PrivateKey routerSigningKey;
    private PublicKey destVerificationKey;
    /**
     *
     */
    private SSUMessage.SSUMessageTypes nextExpected;
    /**
     * Session key for this connection
     */
    private SecretKey sessionKey;
    private KeyPair keyPair;
    private KeyAgreement kex;
    private NonceCache nonceCache;
    private enum ConnectionType {
        CLIENT, SERVER
    }

    private ConnectionType connectionType;

    public SSUConnection(SessionRequest request, PrivateKey routerSigningKey, PublicKey destVerificationKey) {
        this.connectionType = ConnectionType.SERVER;
        this.nextExpected = SSUMessage.SSUMessageTypes.SESSIONCONFIRMED;
        this.nonceCache = new NonceCache(16, 60);

        this.routerSigningKey = routerSigningKey;
        this.destVerificationKey = destVerificationKey;

        setUpKex(); //setup key exchange
    }

    public SSUConnection(PrivateKey routerSigningKey, PublicKey destVerificationKey) {
        this.connectionType = ConnectionType.CLIENT;
        this.nextExpected = SSUMessage.SSUMessageTypes.SESSIONCREATED;
        this.nonceCache = new NonceCache(16, 60);

        this.routerSigningKey = routerSigningKey;
        this.destVerificationKey = destVerificationKey;

        setUpKex(); //setup key exchange
    }

    public SSUMessage handleMessage(SSUMessage message) {
        switch(connectionType) {
            case CLIENT -> {
                return handleClientMessage(message);
            }
            case SERVER -> {
                return handleServerMessage(message);
            }
        }
        throw new IllegalStateException("Bad connection Type" + connectionType);
    }

    private SSUMessage handleClientMessage(SSUMessage message) {
        //handle SSUMessages for the client
        switch(message.getType()) {
            case SESSIONCREATED -> {
                SessionCreated created = (SessionCreated) message;
                if (isNonceRepeat(created.getNonce())) //check nonce
                    return null;
                if (isTypeBad(message.getType())) //check to make sure message is expected
                    return null;

                if (!created.verifySignature(destVerificationKey, sessionKey, keyPair.getPublic())) {
                    log.warn("SSUSocket: could not verify signature ignoring message");
                    return null;
                }

                //add servers pub key
                try {
                    kex.doPhase(created.getDHPub(), true);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e); //key is validated by created message
                }

                // Generate the shared secret
                byte[] sharedSecret = kex.generateSecret();

                //generate session key
                sessionKey = new SecretKeySpec(
                        SCrypt.generate(sharedSecret, created.getIV(),2048, 8, 1, 32), "AES");

                this.nextExpected = SSUMessage.SSUMessageTypes.DATA;

                //send session confirmed
                return new SessionConfirmed(connectionID,keyPair.getPublic(), created.getDHPub(), nonceCache.getNonce(),
                        routerSigningKey, sessionKey);
            }
            case DATA -> {

            }
            case ACK -> {
                //return;
            }
            case SESSIONDESTROYED -> {
                SessionDestroyed destroyed = (SessionDestroyed) message;
                if (isNonceRepeat(destroyed.getNonce())) {
                    return null;
                }

                if (!destroyed.verifyMessage(sessionKey)) {
                    return null;
                }
                //if we return destroyed we will end this connection
                return destroyed;
            }
        }
        throw new IllegalStateException("Bad type of message " + message.getType());
    }

    private SSUMessage handleServerMessage(SSUMessage message) {
        //handle SSUMessage for the server
        switch(message.getType()) {
            case SESSIONREQUEST -> {
                SessionRequest request = (SessionRequest) message;
                //check expected type
                if (isTypeBad(request.getType()))
                //generate shared secret
                try {
                    kex.doPhase(request.getDHPub(), true);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e); //should hit case public key is validated by request
                }
                // Generate the shared secret
                byte[] sharedSecret = kex.generateSecret();

                //generate IV
                byte[] IV = new byte[16];
                random.nextBytes(IV);

                //generate session key
                sessionKey = new SecretKeySpec(
                        SCrypt.generate(sharedSecret, IV,2048, 8, 1, 32), "AES");

                //set next expected
                nextExpected = SSUMessage.SSUMessageTypes.SESSIONCONFIRMED;

                return new SessionCreated(connectionID, keyPair.getPublic(), request.getDHPub(),
                        nonceCache.getNonce(), IV, routerSigningKey, sessionKey);
            }
            case SESSIONCONFIRMED -> {
                SessionConfirmed confirmed = (SessionConfirmed) message;
                if (isNonceRepeat(confirmed.getNonce())) //check nonce of message
                    return null;
                if (isTypeBad(confirmed.getType()))  // check type of message
                    return null;


            }
            case DATA -> {
                Data data = (Data) message;
                if (isNonceRepeat(data.getNonce())) {
                    return null;
                }
                //todo add reliable mode
            }
            case ACK -> {
                //todo add reliable mode
            }
            case SESSIONDESTROYED -> {
                SessionDestroyed destroyed = (SessionDestroyed) message;
                if (isNonceRepeat(destroyed.getNonce())) {
                    return null;
                }

                if (!destroyed.verifyMessage(sessionKey)) {
                    return null;
                }
                //if we return destroyed we will end this connection
                return destroyed;
            }
        }
        throw new IllegalStateException("Bad message type " + message.getType());
    }

    private boolean isTypeBad(SSUMessage.SSUMessageTypes typeToCheck) {
        if (typeToCheck != this.nextExpected) {
            log.warn("SSUConn: Bad type received ignoring message");
            return true;
        }
        return false;
    }

    private boolean isNonceRepeat(byte[] nonce) {
        if (nonceCache.containsNonce(nonce)) {
            log.warn("SSUConn: Message has repeated nonce ignoring message");
            return true;
        }
        nonceCache.addNonce(nonce);
        return false;
    }

    private void setUpKex() {
        try {
            //generate key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            kpg.initialize(new ECGenParameterSpec("X25519"), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            //get key aggreement read
            KeyAgreement kex = KeyAgreement.getInstance("X25519");
            kex.init(keyPair.getPrivate());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e); //setup connection handler
        }
    }
}

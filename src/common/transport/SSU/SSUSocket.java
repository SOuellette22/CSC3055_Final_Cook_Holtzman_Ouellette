package common.transport.SSU;

import common.I2P.I2NP.I2NPHeader;
import common.I2P.I2NP.I2NPMessage;
import common.I2P.I2NP.TunnelData;
import common.I2P.NetworkDB.NetDB;
import common.I2P.NetworkDB.RouterInfo;
import common.I2P.router.Router;
import common.Logger;
import common.transport.I2NPSocket;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;
import org.bouncycastle.crypto.generators.SCrypt;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class SSUSocket extends DatagramSocket{
    /**
     * MAX Size of datagram packets - this is hacky I just set it large in hopes we dont reach it
     */
    private final int MAX_SIZE = 4096;
    private Logger log = Logger.getInstance();
    private NonceCache nonceCache = new NonceCache(16, 60);
    private SecureRandom random = new SecureRandom();
    private int connectionID;
    private SecretKey sessionKey;

    SSUSocket(RouterInfo dest, PrivateKey signingKey) throws IOException {
        super();
        try {
            //create connection ID
            connectionID = random.nextInt();

            //generate key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            kpg.initialize(new ECGenParameterSpec("X25519"), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            //get key aggreement read
            KeyAgreement kex = KeyAgreement.getInstance("X25519");
            kex.init(keyPair.getPrivate());

            //attempt to start a connection
            sendMessage(new SessionRequest(connectionID, keyPair.getPublic()), dest);

            //receive next message
            SSUMessage recvMsg = receiveMessage();
            //check message validity
            checkType(recvMsg.getType(), SSUMessage.SSUMessageTypes.SESSIONCREATED);

            SessionCreated created = (SessionCreated) recvMsg;
            if (nonceCache.containsNonce(created.getNonce())) {
                log.warn("SSUSocket repeated nonce");
                throw new IOException("Repeated message closing connection");
            }

            if (!created.verifySignature(dest.getRouterID().getSigningPublicKey(), sessionKey, keyPair.getPublic())) {
                log.warn("SSUSocket got bad signature on created message");
                throw new IOException("Bad signature closing connection");
            }
            nonceCache.addNonce(created.getNonce()); //add nonce to cache

            //add servers pub key
            kex.doPhase(created.getDHPub(), true);
            // Generate the shared secret
            byte[] sharedSecret = kex.generateSecret();

            //generate session key
            sessionKey = new SecretKeySpec(
                    SCrypt.generate(sharedSecret, created.getIV(),2048, 8, 1, 32), "AES");

            //send session confirmed
            SessionConfirmed confirmed = new SessionConfirmed(connectionID,keyPair.getPublic(), created.getDHPub(), nonceCache.getNonce(),
                    signingKey, sessionKey);
            sendMessage(confirmed, dest);

            log.debug("SSUSocket: connection established");
        }
        catch(InvalidKeyException e) {
            log.warn("Invalid key exception" + e.getMessage());
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e); //should not hit case in prod
        }
    }

    SSUSocket(int port, PrivateKey signingKey) throws IOException {
        super(port);
        try {
            //generate key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            kpg.initialize(new ECGenParameterSpec("X25519"), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            //get key aggreement read
            KeyAgreement kex = KeyAgreement.getInstance("X25519");
            kex.init(keyPair.getPrivate());

            //wait for someone to connect
            SSUMessage recvMsg = receiveMessage();
            connectionID = recvMsg.getConnectionID();

            log.debug("SSUSocket: Got connection " + connectionID);
            checkType(recvMsg.getType(), SSUMessage.SSUMessageTypes.SESSIONREQUEST);
            SessionRequest request = (SessionRequest) recvMsg;

            //generate shared secret
            kex.doPhase(request.getDHPub(), true);
            // Generate the shared secret
            byte[] sharedSecret = kex.generateSecret();

            //generate IV
            byte[] IV = new byte[16];
            random.nextBytes(IV);

            //generate session key
            sessionKey = new SecretKeySpec(
                    SCrypt.generate(sharedSecret, IV,2048, 8, 1, 32), "AES");

            SessionCreated created = new SessionCreated(connectionID, keyPair.getPublic(), request.getDHPub(),
                    nonceCache.getNonce(), IV, signingKey, sessionKey);
            sendMessage(created, null); //todo fix send/recv

            recvMsg = receiveMessage();
            checkType(recvMsg.getType(), SSUMessage.SSUMessageTypes.SESSIONCONFIRMED);

            SessionConfirmed confirmed = (SessionConfirmed) recvMsg;
            if (nonceCache.containsNonce(confirmed.getNonce())) {
                log.warn("SSUSocket repeated nonce");
                throw new IOException("Repeated nonce closing connection");
            }

            //confirmed.verifySignature(null, sessionKey, request.getDHPub(), keyPair.getPublic());
            //todo fix confirmed
            log.debug("SSUSocket: Session established");
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e); //should not hit case in prod
        }
    }

    public void sendMessage(SSUMessage message, RouterInfo toSend) throws IOException {
        byte[] messageByte = message.serialize().getBytes(StandardCharsets.UTF_8);
        if (messageByte.length > MAX_SIZE)
            throw new RuntimeException("Bytes is over max size! We will need to increase max size");

        InetSocketAddress toSendAddress = new InetSocketAddress(toSend.getHost(), toSend.getPort());
        Logger.getInstance().debug("Sending message " + message.getType() + " to " + toSend.getPort());

        DatagramPacket pkt = new DatagramPacket(messageByte, messageByte.length, toSendAddress);
        send(pkt);
    }

    public SSUMessage receiveMessage() throws IOException{
        DatagramPacket pkt = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);
        receive(pkt);

        //this is a hacky trick  to only get bytes received in message real protocols add lengths to avoid this issue
        //We are fake mathematician and Engineers anyways whats a little hack among friends
        String json = new String(pkt.getData(), 0, pkt.getLength(), StandardCharsets.UTF_8);
        JSONObject obj = JsonIO.readObject(json);

        SSUMessage message = new SSUMessage(obj);

        //return SSU meessage based on type
        switch (message.getType()) {
            case SESSIONREQUEST -> {
                return new SessionRequest(obj);
            }
            case SESSIONCREATED -> {
                return new SessionCreated(obj);
            }
            case SESSIONCONFIRMED -> {
                return new SessionConfirmed(obj);
            }
            case SESSIONDESTROYED -> {
                return new SessionDestroyed(obj);
            }
            case DATA -> {
                return new Data(obj);
            }
            case ACK -> {
                return new ACK(obj);
            }
            default -> {
                throw new RuntimeException("Bad type: " + message.getType());
            }
        }
    }

    private void checkType(SSUMessage.SSUMessageTypes typeToCheck, SSUMessage.SSUMessageTypes expectedType) throws IOException {
        if (typeToCheck != expectedType) {
            log.warn("SSUSocket: Bad type received ");
            throw new IOException("Expected " + expectedType + " SSUMessage but got " + typeToCheck);
        }
    }

    public int getConnectionID() {
        return connectionID;
    }
}

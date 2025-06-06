package common.I2P.router;

import common.I2P.I2NP.*;
import common.I2P.NetworkDB.Lease;
import common.I2P.NetworkDB.NetDB;
import common.I2P.NetworkDB.Record;
import common.I2P.NetworkDB.RouterInfo;
import common.I2P.tunnels.*;
import common.Logger;
import common.transport.I2CP.I2CPMessage;
import common.transport.I2CP.PayloadMessage;
import common.transport.I2CP.RequestLeaseSet;
import common.transport.I2NPSocket;
import merrimackutil.util.NonceCache;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Handle incoming I2NP messages
 */
public class RouterServiceThread implements Runnable {
    /**
     * Network database
     */
    private NetDB netDB;
    /**
     * Received I2NP message
     */
    private I2NPHeader recievedMessage;
    /**
     * Source of randomness mainly for message ids
     */
    private SecureRandom random;
    /**
     * This Router's info
     */
    private RouterInfo router;
    /**
     * Logger
     */
    private Logger log;
    /**
     * Is this router a flood fill router
     */
    private boolean isFloodFill;

    /**
     * TunnelManager for this router
     */
    private TunnelManager tunnelManager;

    /**
     * Private key for this router
     */
    private PrivateKey elgamalPrivateKey;

    /**
     * Signing private key for this router
     */
    private PrivateKey signingPrivateKey;
    private NonceCache nonceCache;
    private ConcurrentHashMap<Integer, ConcurrentLinkedQueue<I2CPMessage>> cstMessages;

    /**
     * Create thread to handle router I2NP message
     * 
     * @param networkDatabase Network database of router
     * @param router          RouterInfo of this router
     * @param recievedMessage I2NP message received
     */
    public RouterServiceThread(NetDB networkDatabase, RouterInfo router, I2NPHeader recievedMessage,
            ConcurrentHashMap<Integer, ConcurrentLinkedQueue<I2CPMessage>> cstMessages,
            TunnelManager tunnelManager, PrivateKey elgamalPrivateKey, PrivateKey signingPrivateKey) {
        this.netDB = networkDatabase;
        this.router = router;
        this.recievedMessage = recievedMessage;
        this.random = new SecureRandom();
        this.log = Logger.getInstance();
        this.isFloodFill = false;
        this.tunnelManager = tunnelManager;
        this.cstMessages = cstMessages;
        this.elgamalPrivateKey = elgamalPrivateKey;
        this.signingPrivateKey = signingPrivateKey;
        this.nonceCache = new NonceCache(Integer.BYTES, 60);
    }

    /**
     * Runs this operation.
     */
    @Override
    public void run() {
        if (!recievedMessage.isPayloadValid()) {
            log.debug("Received corrupted payload" + recievedMessage.toJSONType().getFormattedJSON());
            log.warn("Received corrupted payload");
            // return;// corrupt message - may want to add response for reliable send in
            // future
        }
        //get messageID as bytes
        byte[] msgID = ByteBuffer.allocate(Integer.BYTES).putInt(recievedMessage.getMsgID()).array();
        if (nonceCache.containsNonce(msgID)) {
            log.warn("Received repeated message ID dropping message");
            return;
        }
        nonceCache.addNonce(msgID);

        if (recievedMessage.getExpiration() < System.currentTimeMillis()) {
            log.info("Received expired message");
            return; // message has expired throw away
        }
        log.trace("Received message " + recievedMessage.toJSONType().getFormattedJSON());

        switch (recievedMessage.getType()) {
            case DATABASELOOKUP:
                // To avoid trivial DDOS attacks let make sure no one sets the expiration very
                // high for recursive searches
                if (recievedMessage.getExpiration() > System.currentTimeMillis() + 1000) {
                    log.warn("Received message expiration is too high ignoring");
                    return;
                }
                // handle lookup
                DatabaseLookup lookup = (DatabaseLookup) recievedMessage.getMessage();
                log.debug("Handling lookup message ");
                handleLookup(lookup);
                break;
            case DATABASESEARCHREPLY:
                // To avoid trivial DDOS attacks let make sure no one sets the expiration very
                // high for recursive searches
                if (recievedMessage.getExpiration() > System.currentTimeMillis() + 1000) {
                    log.warn("Received message expiration is too high ignoring");
                    return;
                }
                // handle search reply
                DatabaseSearchReply searchReply = (DatabaseSearchReply) recievedMessage.getMessage();
                log.debug("Handling search reply ");
                handleSearchReply(searchReply);
                break;
            case DATABASESTORE:
                DatabaseStore store = (DatabaseStore) recievedMessage.getMessage();
                // add Record to our netDB
                log.debug("Handling store message ");
                handleStore(store);
                break;
            case DELIVERYSTATUS:
                DeliveryStatus status = (DeliveryStatus) recievedMessage.getMessage();
                // todo implement delivery status
                break;
            case TUNNELBUILD:
                // handle tunnel build message
                TunnelBuild tunnelBuild = (TunnelBuild) recievedMessage.getMessage();
                handleTunnelBuildMessage(tunnelBuild);
                break;
            case TUNNELBUILDREPLY:
                // System.out.println("TunnelBuildReplyMessage: " + recievedMessage.toJSONType().getFormattedJSON());
                TunnelBuildReplyMessage tunnelBuildReply = (TunnelBuildReplyMessage) recievedMessage.getMessage();
                handleTunnelBuildReplyMessage(tunnelBuildReply);
                break;
            case TUNNELDATA:
                TunnelDataMessage tunnelData = (TunnelDataMessage) recievedMessage.getMessage();
                handleTunnelDataMessage(tunnelData);
                break;
            default:
                throw new RuntimeException("Bad message type " + recievedMessage.getType()); // should never hit case in
                                                                                             // prod
        }
    }

    private void handleTunnelDataMessage(TunnelDataMessage tunnelData) {
        // get tunnel id from message
        int tunnelID = tunnelData.getTunnelID();

        TunnelObject tunnelObject = tunnelManager.getTunnelObject(tunnelID);

        // get the tunnel from the tunnel manager

        if (cstMessages.containsKey(tunnelID)) {
            EndpointPayload payload = new EndpointPayload(tunnelData.getPayload());

            //fuck it lets do it (this is a hacky cast should work hjahahahahah)
            TunnelEndpoint endpoint = (TunnelEndpoint) tunnelObject;

            payload.finalLayerDecrypt(endpoint.getLayerKey(), endpoint.getIV()); // different values so we gotta use this
            ConcurrentLinkedQueue<I2CPMessage> queue = cstMessages.get(tunnelID);
            queue.add(new PayloadMessage(0, 0, payload.getEncMessage()));
            return;
        }


        if (tunnelObject == null) {
            log.warn("Tunnel object not found for tunnel ID: " + tunnelID);
            return; // Tunnel not found, handle error appropriately
        }

        // handle the message in the tunnel object
        try {
            tunnelObject.handleMessage(tunnelData);
        } catch (IOException e) {
            log.error("Error handling TunnelDataMessage: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean handleTunnelBuildReplyMessage(TunnelBuildReplyMessage tunnelBuildReply) {
        // next tunnel id is the id of the gateway/participant/endpoint we want to send
        // it to
        // while tunnelID is the endpoint of the previous tunnel so we can search for
        // the tunnel
        // and create a lease set for it - only if it is an inbound tunnel of course

        // recursively decrypt the message to get all of the plaintext records
        // all of this will need to change to search the records instead ermmmmmm....
        // later me project me thinks


        if (tunnelManager.getTunnelObject(tunnelBuildReply.getNextTunnel()) != null) {
            TunnelObject tunnelObject = tunnelManager.getTunnelObject(tunnelBuildReply.getNextTunnel());
            try {
                tunnelObject.handleMessage(tunnelBuildReply);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return true;
        }

        // find the tunnelid of the tunnel in the tunnel manager that contains an object
        // with this tunnel id
        // this is bad if this happens there are no inbound or outbound tunnels for a
        // client on this router that contain this id
        int tunnelID = tunnelManager.findAssociatedTunnel(tunnelBuildReply.getTunnelID());
        if (tunnelID == -1) {
            log.error(
                    "Tunnel ID not found in tunnel manager for tunnel build reply: " + tunnelBuildReply.getTunnelID());
            return false; // Tunnel ID not found, handle error appropriately
        }

        if (tunnelManager.getInboundTunnel(tunnelID) != null) {

            // search tunnel manager for the router info of the associated tunnel id
            Tunnel inboundTunnel = tunnelManager.getInboundTunnel(tunnelID);

            // get the router info of the tunnel id
            // RouterInfo routerInfo =
            // inboundTunnel.getTunnelObject(tunnelBuildReply.getTunnelID());
            RouterInfo routerInfo = inboundTunnel.getTunnelObject(tunnelID);

            // get message queue for client
            ConcurrentLinkedQueue<I2CPMessage> cstMsg = cstMessages.get(tunnelBuildReply.getTunnelID());
            if (cstMsg == null) {
                log.error("Client did not create queue under the right ID");
                return false;
            }
            Lease lease = new Lease(routerInfo.getRouterID(), inboundTunnel.getGatewayTunnelID());

            ArrayList<Lease> leases = new ArrayList<>();
            leases.add(lease);
            // give client lease for this inbound tunnel
            RequestLeaseSet requestLeaseSet = new RequestLeaseSet(0, leases);
            cstMsg.add(requestLeaseSet);
        }

        return true;
    }

    private void handleTunnelBuildMessage(TunnelBuild tunnelBuild) {
        // iterate through all the records and compare the first 16 bytes of the hash
        // to the toPeer field of the record, if they match we have found the correct
        // record for us
        //our record
        String base64ourIdent = Base64.getEncoder().encodeToString(Arrays.copyOf(router.getHash(), 16));

        // for each record in the tunnel build message attempt to decrypt it with our secret key
        // if it decrypts and too peer matches we found our record -- other wise we replace it back with its original encrypted self
        // and move on to the next record
        TunnelBuild.Record ourRecord = null;
        for (TunnelBuild.Record record : tunnelBuild.getRecords()) {
            TunnelBuild.Record temp = new TunnelBuild.Record(record); // unsure if this will deserialze properly
            try {
            record.hybridDecrypt(elgamalPrivateKey);
            } catch (Exception e) {
                continue; // skip this record if we can't decrypt its expected
            }
            if (Arrays.equals(record.getToPeer(), Base64.getDecoder().decode(base64ourIdent))) {
                ourRecord = record;
                // once we find our record we can aes decrypt every record after it
                // and then break out of the loop
                for (int i = tunnelBuild.getRecords().indexOf(record) + 1; i < tunnelBuild.getRecords().size(); i++) {
                    TunnelBuild.Record nextRecord = tunnelBuild.getRecords().get(i);
                    nextRecord.layeredDecrypt(ourRecord.getReplyKey(), ourRecord.getReplyIv());
                }
                break;
            }
            record = new TunnelBuild.Record(temp); // create a new instance to ensure it's a copy
        }

        // grrreat now we have our keys! from here we need to aes decrypt each record after this one with the reply key
        // Use the reply key from our record to AES decrypt every record after it


        if (ourRecord == null) {
            log.error("Could not find our record disregarding");
            return;
        }



        /*
        tunnelBuild.decryptAES(ourRecord.getReplyKey());
        JSONObject jsonObject = JsonIO.readObject(new String(ourRecord.getEncData(), StandardCharsets.UTF_8));

        try {
            ourRecord = new TunnelBuild.Record(jsonObject);
        } catch (InvalidObjectException e) {
            throw new RuntimeException(e);
        }
        *
         */
        if (System.currentTimeMillis() > ourRecord.getRequestTime() + 60000) { // allow for 1 minute for
            // tunnelBuild
            log.warn("Invalid timestamp in tunnel request. Dropping record.");
            return;
        }

        // byte[] replyBlock = createReplyBlock(record);
        // record.setEncData(replyBlock);

        byte[] nextIdent = ourRecord.getNextIdent();

        // temp before enc
        common.I2P.I2NP.TunnelBuild.Record replyRecord = createReplyBlock(ourRecord);
        // hey sam seth here we are doing this then checking if it's an endpoint?
        // record = replyRecord; // replace the record with the reply block

        // Add the tunnel to the TunnelManager
        addTunnelToManager(ourRecord);

        // Handle endpoint behavior
        if (ourRecord.getPosition() == TunnelBuild.Record.TYPE.ENDPOINT) {
            handleEndpointBehavior(tunnelBuild, ourRecord);
        } else {
            try {
                // forward build request to next hop
                I2NPSocket nextHopSocket = new I2NPSocket();
                I2NPHeader header = new I2NPHeader(I2NPHeader.TYPE.TUNNELBUILD, random.nextInt(),
                        System.currentTimeMillis() + 100, tunnelBuild);
                RouterInfo nextRouter = validatePeerRouter(ourRecord.getNextIdent());

                if (nextRouter == null) {
                    log.error("Could not find gateway "
                            + Base64.getEncoder().encodeToString(ourRecord.getNextIdent()));
                    return;
                }

                nextHopSocket.sendMessage(header, nextRouter);
                nextHopSocket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        // note to self - how do we adjust for recursive decryption on reply records?
    }

    private void handleEndpointBehavior(TunnelBuild tunnelBuild, common.I2P.I2NP.TunnelBuild.Record record) {
        TunnelBuildReplyMessage replyMessage;
        // realistically have a check here that all reply flags are set to true
        replyMessage = new TunnelBuildReplyMessage(record.getNextTunnel(), record.getReceiveTunnel(), tunnelBuild); // pack the entire message in the build reply
        // System.out.println("TunnelBuildReplyMessage: " + replyMessage.toJSONType().getFormattedJSON());
        // System.out.println("replyMessage: " + replyMessage.toJSONType().getFormattedJSON());
        // query netdb for router info of next hop
        RouterInfo nextRouter = validatePeerRouter(record.getNextIdent());
        if (nextRouter == null) {
            log.error("Could not find endpoint " + Base64.getEncoder().encodeToString(record.getNextIdent()));
            return;
        }

        // forward message to next hop
        I2NPSocket nextHopSocket = null;
        try {
            nextHopSocket = new I2NPSocket();
            // create new header
            I2NPHeader header = new I2NPHeader(I2NPHeader.TYPE.TUNNELBUILDREPLY, random.nextInt(),
                    System.currentTimeMillis() + 100, replyMessage);
            nextHopSocket.sendMessage(header, nextRouter); // send directly to router
            // this may need to changed in final implementation for security reasons
            nextHopSocket.close();
        } catch (IOException e) {
            if (nextHopSocket != null)
                nextHopSocket.close();
            log.error("Error sending TunnelBuildReply message: " + e.getMessage());
        }
        return;
    }

    // switch thsi from bytes to record and have sendmsgid be the reply bit
    // yyyyyasudyasukdghasjhdgashjdgha
    private common.I2P.I2NP.TunnelBuild.Record createReplyBlock(common.I2P.I2NP.TunnelBuild.Record record) {
        // go through the record and replace everything with a random value
        // however, make sendmsgid be 0

        // to peer bytes
        Random random = new Random();
        byte[] toPeer = new byte[16];
        random.nextBytes(toPeer);

        // receive tunnel id int
        int receiveTunnel = random.nextInt(1000);

        // our ident bytes
        byte[] ourIdent = new byte[32];
        random.nextBytes(ourIdent);

        // next tunnel id int
        int nextTunnel = random.nextInt(1000);

        // next ident byte
        byte[] nextIdent = new byte[32];
        random.nextBytes(nextIdent);

        // layer key secret
        SecretKey layerKey = new SecretKeySpec(new byte[32], "AES");
        random.nextBytes(layerKey.getEncoded());

        // random iv bytes
        byte[] layerIv = new byte[16];
        random.nextBytes(layerIv);

        // iv key secret
        SecretKey ivKey = new SecretKeySpec(new byte[32], "AES");
        random.nextBytes(ivKey.getEncoded());

        // reply key secret
        SecretKey replyKey = new SecretKeySpec(new byte[32], "AES");
        random.nextBytes(replyKey.getEncoded());

        // reply iv bytes
        byte[] replyIv = new byte[16];
        random.nextBytes(replyIv);

        // request time long
        long requestTime = System.currentTimeMillis() / 1000; // epoch time in seconds
        // send msg id int
        int sendMsgID = 0; // set to 0 for successful reply

        // pick random type
        TunnelBuild.Record.TYPE type = TunnelBuild.Record.TYPE.PARTICIPANT; // this is general enough

        // reply flag set to true here
        // this is also temp plain text
        TunnelBuild.Record replyRecord = new TunnelBuild.Record(toPeer, receiveTunnel, ourIdent, nextTunnel,
                nextIdent, layerKey, layerIv, ivKey, replyKey, replyIv, requestTime, sendMsgID, type, null, true);

        // we need to encrypt this but for now return the record
        // like this should return bytes in the future
        // new Record(toPeer, encData);

        return replyRecord;
    }

    private void addTunnelToManager(TunnelBuild.Record record) {
        if (record.getPosition() == TunnelBuild.Record.TYPE.GATEWAY) {
            TunnelGateway tunnelGateway = new TunnelGateway(
                    record.getReceiveTunnel(),
                    record.getLayerKey(),
                    record.getLayerIv(),
                    record.getIvKey(),
                    record.getReplyKey(),
                    record.getReplyIv(),
                    record.getNextIdent(),
                    record.getNextTunnel(),
                    router,
                    record.getHopInfo(),
                    netDB);
            tunnelManager.addTunnelObject(record.getReceiveTunnel(), tunnelGateway);
            log.info("Added tunnel gateway for tunnel ID: " + record.getReceiveTunnel());
        } else if (record.getPosition() == TunnelBuild.Record.TYPE.ENDPOINT) {
            TunnelEndpoint tunnelEndpoint = new TunnelEndpoint(
                    record.getReceiveTunnel(),
                    record.getLayerKey(),
                    record.getLayerIv(),
                    record.getIvKey(),
                    record.getReplyKey(),
                    record.getReplyIv(),
                    router.getHash(),
                    router.getPort(),
                    netDB);
            tunnelManager.addTunnelObject(record.getReceiveTunnel(), tunnelEndpoint);
            log.info("Added tunnel endpoint for tunnel ID: " + record.getReceiveTunnel());
        } else {
            TunnelParticipant tunnelParticipant = new TunnelParticipant(
                    record.getReceiveTunnel(),
                    record.getLayerKey(),
                    record.getLayerIv(),
                    record.getIvKey(),
                    record.getReplyKey(),
                    record.getReplyIv(),
                    record.getNextIdent(),
                    record.getNextTunnel(),
                    netDB);
            tunnelManager.addTunnelObject(record.getReceiveTunnel(), tunnelParticipant);
            log.info("Added tunnel participant for tunnel ID: " + record.getReceiveTunnel());
        }
    }

    private void handleLookup(DatabaseLookup lookup) {
        // send reply directly to router requesting it
        Record requestRouter = netDB.lookup(lookup.getFromHash());
        if (lookup.getReplyFlag() == 0) {
            // check if we dont know where to send message to
            if (requestRouter == null) {
                log.trace("Could not find peer: " + Base64.getEncoder().encodeToString(lookup.getFromHash()));
                // attempt to find peer for reply we will wait 10 milli seconds
                findPeerRecordForReply(50, lookup.getFromHash());
                requestRouter = netDB.lookup(lookup.getFromHash());
                // if we still do not know give up
                if (requestRouter == null) {
                    log.warn("Could not find who sent lookup even after asking peers fromHash: "
                            + Base64.getEncoder().encodeToString(lookup.getFromHash()));
                    return;
                }
            }
        }
        if (lookup.getReplyFlag() == 1) {
            // todo add sending reply down some tunnel
        }

        if (requestRouter.getRecordType() == Record.RecordType.LEASESET) {
            // todo handle this case, question for sam can we use leaseSets to send a
            // message
            return;
        }
        // result message
        I2NPHeader result;
        // try to find record
        Record record = netDB.lookup(lookup.getKey());

        if (record != null) { // we have record in database

            log.trace("Found Record in NetDB");
            // store record
            DatabaseStore storeData;

            // we will check for a special bootstrap/verification lookup, where a peer is
            // trying to lookup themeself if so
            // we will send back our info instead of requested info
            if (Arrays.equals(lookup.getKey(), lookup.getFromHash())) {
                log.trace("Bootstrapping/verification sending store as response");
                // we will send back our own info in this case
                storeData = new DatabaseStore(router);
            } else {
                // normal store request so we will just add record we found
                storeData = new DatabaseStore(record);
            }

            result = new I2NPHeader(I2NPHeader.TYPE.DATABASESTORE, recievedMessage.getMsgID(),
                    System.currentTimeMillis() + 100,
                    storeData); // create store message if we found record

        }
        // if no record found send search reply with closest peers
        else {
            log.trace("Record not found sending nearest neighbors");
            // get hashes of closest peers that could have key
            ArrayList<byte[]> closestPeersHashes = new ArrayList<>();
            for (RouterInfo currPeer : netDB.getKClosestRouterInfos(lookup.getKey(), 3)) {
                closestPeersHashes.add(currPeer.getHash());
            }
            // create message to send to requesting router make sure to decrease expiration
            // so search will timeout
            result = new I2NPHeader(I2NPHeader.TYPE.DATABASESEARCHREPLY, recievedMessage.getMsgID(),
                    recievedMessage.getExpiration() - 10,
                    new DatabaseSearchReply(lookup.getKey(), closestPeersHashes, router.getHash()));
        }

        // lets send our lookup response back to peer who requested it
        // assuming here it is RouterInfo might need to change later once leaseSets are
        // implemented
        RouterInfo requestRouterInfo = (RouterInfo) requestRouter;
        I2NPSocket respondSock = null;
        try {
            respondSock = new I2NPSocket();
            respondSock.sendMessage(result, requestRouterInfo);
            respondSock.close();
        } catch (IOException e) {
            if (respondSock != null)
                respondSock.close();
            System.err.println("could not send message I/O error " + e.getMessage());
        }
        log.trace("Response message is " + result.toJSONType().getFormattedJSON());

    }

    private void handleSearchReply(DatabaseSearchReply searchReply) {
        // query closest peers to see if they have the hash
        ArrayList<byte[]> peerHash = searchReply.getPeerHashes();
        I2NPSocket peerSocket = null;
        try {
            peerSocket = new I2NPSocket();
        } catch (SocketException e) {
            log.warn("RST: Could not connect on socket " + e.getMessage());
            return;
        }

        for (byte[] hash : peerHash) {
            Record peerRecord = netDB.lookup(hash);

            if (peerRecord == null) {
                // attempt to find peer lets wait 5 ms for each reply
                findPeerRecordForReply(10, hash);
            }

            // check if we found peer if so send lookup message
            peerRecord = netDB.lookup(hash);
            // if still null let's just try the next peer
            if (peerRecord == null) {
                continue;
            }

            switch (peerRecord.getRecordType()) {
                case ROUTERINFO -> {
                    // send lookup request to peer
                    RouterInfo peerRouterInfo = (RouterInfo) peerRecord;

                    try {
                        // we will decrease expiration so recursive search expires
                        I2NPHeader lookupMessage = new I2NPHeader(I2NPHeader.TYPE.DATABASELOOKUP, random.nextInt(),
                                recievedMessage.getExpiration() - 10,
                                new DatabaseLookup(searchReply.getKey(), router.getHash()));
                        peerSocket.sendMessage(lookupMessage, peerRouterInfo);
                    } catch (IOException e) {
                        log.warn("Could not connect/send message to peer" + e.getMessage());
                        peerSocket.close();
                    }
                }
                case LEASESET -> {
                    // todo add support for leasesets
                }
            }
        }
        peerSocket.close();
    }

    private void handleStore(DatabaseStore store) {
        // if we do not have record we use floodfill record by sending it to 3
        // friends(Routers)
        if (isFloodFill && (netDB.lookup(store.getKey()) == null)) {
            ArrayList<RouterInfo> closestPeers = netDB.getKClosestRouterInfos(store.getKey(), 3);
            I2NPSocket floodSock = null;
            try {
                // create socket to send store request to peers
                floodSock = new I2NPSocket();
            } catch (SocketException e) {
                System.err.println("Could not connect to peers " + e.getMessage());
            }

            // send store request to nearest peers
            for (RouterInfo peer : closestPeers) {
                log.trace("Sending flood store to peer: " + peer.getPort());
                // create send store request, we will say store request valid for 100 ms(store
                // request ok to live longer)
                I2NPHeader peerMSG = new I2NPHeader(I2NPHeader.TYPE.DATABASESTORE, random.nextInt(),
                        System.currentTimeMillis() + 100, new DatabaseStore(store.getRecord()));
                // send message to peer
                try {
                    floodSock.sendMessage(peerMSG, peer);
                } catch (IOException e) {
                    log.error("RST: Issue in floodfill connecting to peer ", e);
                }
            }
            // close socket if created
            if (floodSock != null)
                floodSock.close();

        }
        // add Record to our netDB
        netDB.store(store.getRecord());

        if (store.getReplyToken() > 0) {
            DeliveryStatus deliveryStatus = new DeliveryStatus(recievedMessage.getMsgID(), System.currentTimeMillis());
            int tunnelID = store.getReplyTunnelID(); // this is set in setReply but setReply is never called so this is
                                                     // null
            byte[] replyGatewayHash = store.getReplyGateway(); // see prev comment
            try {
                I2NPSocket replySock = new I2NPSocket();
                I2NPHeader replyMessage = new I2NPHeader(I2NPHeader.TYPE.DELIVERYSTATUS, random.nextInt(),
                        System.currentTimeMillis() + 100, deliveryStatus);
                // send delivery status directly to the router, no tunnels (chicken and egg?)
                // uhhhhh i think i can make tunnels before this? maybe? idk
                // well actually were doing a direct query to this router anyways so a direct
                // reply is fine

            } catch (SocketException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }

    }

    /**
     * Attempt to find peer to reply to them, we will do this by sending lookups to
     * close routers, we will wait some time
     * to allow network to search for record then we will try again
     * 
     * @param msToWait milliseconds we want to wait for reply to come in from
     *                 routers we know about
     * @param fromHash Hash of peer we need information about
     */
    private void findPeerRecordForReply(int msToWait, byte[] fromHash) {
        // we will ask two of our buddies to see if we could find info to send to
        // information back to this router
        ArrayList<RouterInfo> closestPeers = netDB.getKClosestRouterInfos(fromHash, 3);
        I2NPSocket peerSock = null;
        log.trace("Going to ask " + closestPeers.size());
        try {
            peerSock = new I2NPSocket();
            for (RouterInfo peer : closestPeers) {

                log.trace("Asking peer port: " + peer.getPort() + " to find: "
                        + Base64.getEncoder().encodeToString(fromHash));
                I2NPHeader peerLookup = new I2NPHeader(I2NPHeader.TYPE.DATABASELOOKUP, random.nextInt(),
                        System.currentTimeMillis() + 100, new DatabaseLookup(fromHash, router.getHash()));
                peerSock.sendMessage(peerLookup, peer);
            }

            Thread.sleep(msToWait); // wait for results
            peerSock.close();
        } catch (IOException e) {
            log.warn("Could not connect to peers" + e);
            if (peerSock != null)
                peerSock.close(); // close sock if possible
        } catch (InterruptedException e) {
            log.warn("Sleep was interrupted");
            peerSock.close();
        }
    }

    /**
     * Verify that a peer exists in NetDB and they are a RouterInfo - will attempt
     * to find them if they are not in netDB
     *
     * @param hash Hash of peer to validate
     * @return RouterInfo of peer or null if they do not exist
     */
    private RouterInfo validatePeerRouter(byte[] hash) {
        Record record = netDB.lookup(hash);
        if (record == null || record.getRecordType() == Record.RecordType.LEASESET) {
            findPeerRecordForReply(100, hash); // if record is bad ask our friends to find proper one
            record = netDB.lookup(hash);
        }
        if (record == null || record.getRecordType() == Record.RecordType.LEASESET) // if still bad return null
            return null;
        return (RouterInfo) record;
    }

    /**
     * Get the received message - temp method for testing
     * 
     * @return I2NPHeader message received
     */
    public void setReceivedMessage(I2NPHeader mockHeader) {
        this.recievedMessage = mockHeader;
    }

    /**
     * Turn on floodfill algorithm for new store requests to this router
     *
     * @param isFloodFill Boolean to turn floodfill on/off
     */
    public void setFloodFill(boolean isFloodFill) {
        this.isFloodFill = isFloodFill;
    }
}

package common.I2P.router;

import common.Logger;
import common.transport.SSU.*;

import java.io.IOException;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;

public class ConnectionManager {
    private ConcurrentHashMap<Integer, SSUConnection> connections;
    private ConcurrentHashMap<Integer, Socket> clientSockets;
    private Logger log = Logger.getInstance();
    private SecureRandom random = new SecureRandom();
    private SSUMessage message;
    private String host = null;
    private Integer port = null;

    public ConnectionManager() {
        this.connections = new ConcurrentHashMap<>();
        this.clientSockets = new ConcurrentHashMap<>();
    }

   public void addConnection(SessionRequest request, PrivateKey signingKey, PublicKey verificationKey) throws IOException {
        connections.put(request.getConnectionID(), new SSUConnection(request, signingKey, verificationKey));
        clientSockets.put(request.getConnectionID(), new Socket(host,port));
   }

   public void addConnection(PrivateKey signingKey, PublicKey verificationKey) throws IOException {
        int connectionID = random.nextInt();
        connections.put(connectionID, new SSUConnection(connectionID, signingKey, verificationKey));
   }
]
}

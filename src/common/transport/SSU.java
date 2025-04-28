package common.transport;

import common.I2P.NetworkDB.RouterInfo;
import common.Logger;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.SocketException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Our implementation of a skimmed down Secure Socket C
 */
public class SSU {
    /**
     * I2NP Socket to send information over network
     * @param router
     */
    private I2NPSocket netSock;
    private RouterInfo router;
    private RouterInfo destRouter;
    private SecureRandom random = new SecureRandom();
    private Logger log = Logger.getInstance();
    private PrivateKey privateKey;


    SSU(RouterInfo router, SecretKey aesKey) throws SocketException {

    }
    SSU(RouterInfo router, RouterInfo destRouter) throws IOException {
        this.router = router;
        this.destRouter = destRouter;

        //start session
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            kpg.initialize(new ECGenParameterSpec("X25519"), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();

            privateKey = keyPair.getPrivate();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //should not hit case
        }
    }
}

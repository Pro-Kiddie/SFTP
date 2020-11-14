
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author yang_
 */
public class Trusted {

    //Class Variables
    final static String TRUSTED_PVT_KEY_FILE = "trusted/trusted.pfx";
    final static int TRUSTED_SOCKET_PORT = 16555;
    final static String RSA_ENC_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    final static long TIMESTAMP_LIMIT = 300000; //30 000 millisecond = 5 minutes
    final static String TRUSTED_VERIFIED_PATH = "trusted/verified";
    final static String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    public static void main(String[] args) {

        //1. Read trusted's private key into memory
        Path path = Paths.get(TRUSTED_PVT_KEY_FILE);
        PrivateKey trustedPvtKey = null;
        KeyFactory kfRSA = null;
        try {
            byte[] trustedPvtKeyBytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(trustedPvtKeyBytes);
            kfRSA = KeyFactory.getInstance("RSA");
            trustedPvtKey = kfRSA.generatePrivate(pkcs8);
        } catch (IOException e) {
            System.out.println("Trust's private key is not found.");
            System.exit(1);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error. Failed to start server. Corrupted trusted private key.");
            System.exit(1);
        }

        //Method Variables
        SimpleDateFormat dateFormat = new SimpleDateFormat("yy/MM/dd HH:mm:ss");

        //2. Start listening for connections from server/client
        try (ServerSocket trustedSocket = new ServerSocket(TRUSTED_SOCKET_PORT)) {
            
            while (true) {
                System.out.println(dateFormat.format(new Date()) + ": Trusted server started. Listening on Port: " + TRUSTED_SOCKET_PORT);

                //3. Accept new connection from server/client
                //Use try-with-resource syntax so the socket with client/server is always closed after the clause
                //When socket is closed, the corresponding Input/Output Stream is also closed
                try (Socket socket = trustedSocket.accept()) {
                    System.out.println("======================== NEW CONNECTION =========================");
                    System.out.println(dateFormat.format(new Date()) + ": Accepted connection from " + socket.getRemoteSocketAddress().toString());
                    //Connection Variables
                    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                    ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

                    //4. Receive server/client's request
                    //Request contains ownID (Encrypted), requestID (Encrypted), Timestamp (Encrypted)
                    System.out.println("Receiving request from client/server ...");
                    ArrayList<byte[]> request = (ArrayList<byte[]>) ois.readObject();
                    System.out.println("Request received. Verifying it's timestamp ...");

                    //5. Decrypt and compare Timestamp with current time. 
                    //If not within +- 5 minutes, close socket and back to listening state
                    Cipher rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
                    rsaCipher.init(Cipher.DECRYPT_MODE, trustedPvtKey);
                    byte[] timestampBytes = rsaCipher.doFinal(request.get(2));
                    if (!validTimestamp(timestampBytes)) {
                        System.out.println("Invalid timestamp. Request is more than 5 minutes old. Dropping connection.");
                        System.out.println("======================== END OF CONNECTION ======================");
                        continue;
                    }
                    System.out.println("Valid timestamp.");

                    //6. Decrypt ownID & requestID using Trusted's private key 
                    //(Encrypted to protect Server & Client's ID)
                    System.out.println("Decrypting serverID/clientID ...");
                    String id = new String(rsaCipher.doFinal(request.get(0)));
                    String requestID = new String(rsaCipher.doFinal(request.get(1)));
                    System.out.println("Done.");

                    //7. Read serverID/clientID's public key from its corresponding public key file in the "verified" folder 
                    //Verified folder stores all the authenticated servers/clients's public keys
                    System.out.println("Retrieving server/client's public key ...");
                    path = Paths.get(TRUSTED_VERIFIED_PATH, id + ".pub");
                    //If public key file does not exist -> Invalid ID -> Close socket and back to listening state
                    if (!Files.exists(path)) {
                        System.out.println("Invalid ServerID/ClientID. Public key doesn't exist. Dropping Connection.");
                        //No need to explicitly close socket because of try-with-resource syntax
                        System.out.println("======================== END OF CONNECTION ======================");
                        continue;
                    }
                    byte[] idPubKeyBytes = Files.readAllBytes(path);
                    X509EncodedKeySpec x509 = new X509EncodedKeySpec(idPubKeyBytes);
                    PublicKey idPubKey = kfRSA.generatePublic(x509);
                    System.out.println("Done.");

                    //8. Read requestID's public key from its corresponding public key file in the "verified" folder
                    System.out.println("Retrieving requested's public key ...");
                    path = Paths.get(TRUSTED_VERIFIED_PATH, requestID + ".pub");
                    //If public key file does not exist -> Invalid ID -> Close socket and back to listening state
                    if (!Files.exists(path)) {
                        System.out.println("Invalid ServerID/ClientID. Public key doesn't exist. Dropping Connection.");
                        System.out.println("======================== END OF CONNECTION ======================");
                        continue;
                    }
                    byte[] reqPubKeyBytes = Files.readAllBytes(path);
                    x509 = new X509EncodedKeySpec(reqPubKeyBytes);
                    PublicKey requestPubKey = kfRSA.generatePublic(x509);
                    System.out.println("Done.");

                    //9. Generate a signature for the requestID's public key retrieved
                    System.out.println("Signing requested's public key ...");
                    byte[] signature = signReqPubKey(trustedPvtKey, requestPubKey.getEncoded());
                    System.out.println("Done. ");

                    //10. Encrypt the timestamp received using server/client's public key
                    rsaCipher.init(Cipher.ENCRYPT_MODE, idPubKey);
                    System.out.println("Encrypting timestamp with server/client's public key ...");
                    byte[] encTimestampBytes = rsaCipher.doFinal(timestampBytes);
                    System.out.println("Done. ");

                    //11. Send (request public key, signature, timestamp) back to server/client
                    System.out.println("Sending reply back to server/client ...");
                    ArrayList<byte[]> reply = new ArrayList<>();
                    reply.add(requestPubKey.getEncoded());
                    reply.add(signature);
                    reply.add(encTimestampBytes);
                    oos.writeObject(reply);
                    System.out.println("Done.");

                    //Served a server/client. Going back to listening state
                    System.out.println(dateFormat.format(new Date()) + ": Sent " + requestID + "'s public key to " + id + ".");
                    System.out.println("======================== END OF CONNECTION ======================");
                    //No need to explicitly close socket because of try-with-resource syntax
                    
                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | SignatureException e) {
                    //e.printStackTrace();
                    System.out.println("Error. Connection closed.");
                    System.out.println("======================== END OF CONNECTION ======================");
                }
            }
        } catch (Exception e) {
            //e.printStackTrace();
            System.out.println("Server stopped.");
        }
    }
    
    public static boolean validTimestamp(byte[] timestampBytes) {
        long now = System.currentTimeMillis();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(timestampBytes);
        buffer.flip();
        long timestamp = buffer.getLong();
        return (now - timestamp) < TIMESTAMP_LIMIT;
    }
    
    public static byte[] signReqPubKey(PrivateKey pvtKey, byte[] pubKeyBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM);
        sign.initSign(pvtKey);
        sign.update(pubKeyBytes);
        return sign.sign();
    }
}

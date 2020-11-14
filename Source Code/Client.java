
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author yang_
 */
public class Client {

    //Class Variables
    private static final String CLIENT_PVT_KEY_FILE = "client/client.pfx";
    private static final String TRUSTED_PUB_KEY_FILE = "client/trusted.pub";
    private static final String TRUSTED_IP = "127.0.0.1";
    //private static final String SERVER_IP = "127.0.0.1";
    private static final int TRUSTED_PORT = 16555;
    private static final int SERVER_PORT = 16666;
    private static final String RSA_ENC_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ENC_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String CLIENT_ID = "client";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String HASHING_ALGORITHM = "SHA-256";
    private static final Map<String, String> ipMap;
    static {
        Map<String, String> aMap = new HashMap<String,String>();
        aMap.put("Server", "127.0.0.1");
        ipMap = Collections.unmodifiableMap(aMap);
    }
    
    public static void main(String[] args) {
        
        //Ensure sufficient argument is passed in
        if (args.length != 1){
            System.out.println("Usage: java ./Client <ServerID>");
            System.exit(1);
        }
        String serverID = args[0]; //ServerID which indicates the server the client wants to connect to
        
        //1. Read client's own private key
        Path path = Paths.get(CLIENT_PVT_KEY_FILE);
        PrivateKey clientPvtKey = null;
        KeyFactory kfRSA = null;
        try {
            byte[] clientPvtKeyBytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(clientPvtKeyBytes);
            kfRSA = KeyFactory.getInstance("RSA");
            clientPvtKey = kfRSA.generatePrivate(pkcs8);
        } catch (IOException e) {
            System.out.println("Client's private key is not found.");
            System.exit(1);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error. Failed to start client. Corrupted client private key.");
            System.exit(1);
        }

        //2. Read trusted's public key
        path = Paths.get(TRUSTED_PUB_KEY_FILE);
        X509EncodedKeySpec x509 = null;
        PublicKey trustedPubKey = null;
        try {
            byte[] trustedPubKeyBytes = Files.readAllBytes(path);
            x509 = new X509EncodedKeySpec(trustedPubKeyBytes);
            trustedPubKey = kfRSA.generatePublic(x509);
        } catch (IOException e) {
            System.out.println("Trusted's public key is not found.");
            System.exit(1);
        } catch (InvalidKeySpecException e) {
            System.out.println("Error. Failed to start client. Corrupted trusted public key.");
            System.exit(1);
        }

        //Method variables
        SimpleDateFormat imageNameFormat = new SimpleDateFormat("yyyy-MM-dd_HHmmss");

        //3. Establish connection with trusted and retrieve legitimate server public key
        System.out.println("===================== CONNECTION WITH TRUSTED ======================");
        System.out.println("Retrieved legitimate public key of " + serverID + " from Trusted.");
        PublicKey serverPubKey = getPubKeyFromTrusted(CLIENT_ID, serverID, trustedPubKey, clientPvtKey);
        if (serverPubKey == null) {
            //Error when retrieving public key from trusted, quit the program
            System.out.println("Unable to retrieve legitimate public key from Trusted.");
            return;
        }
        System.out.println("Done");
        System.out.println("================= CONNECTION WITH TRUSTED CLOSED ===================");
        //4. Establish connection with server
        System.out.println("===================== CONNECTION WITH SERVER =======================");
        try (Socket serverSkt = new Socket(ipMap.get(serverID), SERVER_PORT)) {
            while (true) {
                ObjectOutputStream oos = new ObjectOutputStream(serverSkt.getOutputStream());
                ObjectInputStream ois = new ObjectInputStream(serverSkt.getInputStream());
                //5. Generate OTP1
                SecureRandom randOTP = new SecureRandom();
                byte[] otp1 = new byte[8];
                randOTP.nextBytes(otp1);
                
                //6. Establish session with server
                System.out.println("==================== NEW SESSION WITH SERVER =======================");
                System.out.println("Establishing a new session with server.");
                SecretKey aesSessKey = getSessWithServer(serverSkt, serverPubKey, otp1, clientPvtKey, oos, ois);
                if (aesSessKey == null) {
                    System.out.println("Unable to establish session with server.");
                    throw new IOException();
                }
                System.out.println("Session established.");
                
                //Create a folder named serverID to store the images if it does not exists
                path = Paths.get("client", serverID );
                Files.createDirectories(path);
                
                //AES cipher to decrypt data
                Cipher aesCipher = Cipher.getInstance(AES_ENC_ALGORITHM);
                aesCipher.init(Cipher.DECRYPT_MODE, aesSessKey);
                //Digest to generate hash
                MessageDigest digest = MessageDigest.getInstance(HASHING_ALGORITHM);
                
                //7. Retrieve reply[(image,hash) or OTP1) from server in a while loop 
                while (true) {
                    try {
                        //a. Receive reply from server
                        System.out.println("Receiving data from server.");
                        ArrayList<byte[]> reply = (ArrayList<byte[]>) ois.readObject();                      

                        //b. decrypt reply[0] and check if it is equal to OTP1
                        byte[] item1 = aesCipher.doFinal(reply.get(0));
                        if (Arrays.equals(otp1, item1)) {
                            System.out.println("Server signal to renew session.");                           
                            //c. if equal to OTP1 break the loop to restablish session to renew session key
                            System.out.println("========================= SESSION ENDED  ===========================");
                            break;
                        }
                        
                        //d. Reply is image. Encrypted image with hash. 
                        //e. Generate the hash of the encrypted image
                        //Better to encrypt image first then hash compared to hash then encrypt. 
                        //As the latter expose the hash of the original plaintext. Can be bruteforced
                        System.out.println("Generating hash of encrypted image.");
                        byte[] item1Hash = digest.digest(reply.get(0));
                        byte[] recHash = reply.get(1);
                        if (!Arrays.equals(item1Hash, recHash)) {
                            //f. If hash does not match, corrupted image -> ignore this image
                            System.out.println("Image corrupted. Ignore image.");
                            continue;
                        }
                        System.out.println("Image genuine.");
                        
                        //h. Save the image
                        byte[] imageBytes = item1;
                        System.out.println("Saving image to a file.");
						String fName = "client/" + serverID + "/" + imageNameFormat.format(new Date()) + ".jpg";
                        try (FileOutputStream fos = new FileOutputStream(fName)) {
                            fos.write(imageBytes);
                        } catch (IOException e) {
                            System.out.println("Error writing image to file.");
                        }
                        System.out.println("Image saved to: " + fName);
                        
//                        //i. Tell server I AM READY TO RECEIVE NEXT IMAGE
//                        ArrayList<byte[]> ack = new ArrayList<>();
//                        aesCipher.init(Cipher.ENCRYPT_MODE, aesSessKey);
//                        ack.add(aesCipher.doFinal("ACK".getBytes()));
//                        oos.writeObject(ack);
                        
                        //j. Receive the next image
                    } catch (BadPaddingException | ClassNotFoundException | IllegalBlockSizeException e) {
                        System.out.println("Session error with server. Trying to establish a new session.");
                        //e.printStackTrace();
                    }
                }
            }

            //8. User press CTRL+C to stop the retrival of image
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("=================== CONNECTION WITH SERVER ENDED ====================");
            //e.printStackTrace();
        }
    }

    public static byte[] generateTimestamp() {
        long now = System.currentTimeMillis();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(now);
        return buffer.array();
    }

    public static boolean verifySignature(PublicKey pubKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa256 = Signature.getInstance(SIGNATURE_ALGORITHM);
        rsa256.initVerify(pubKey);
        rsa256.update(data);
        return rsa256.verify(signature);
    }

    public static PublicKey getPubKeyFromTrusted(String ownID, String requestID, PublicKey trustedPubKey, PrivateKey ownPvtKey) {
        //Method variables
        Cipher rsaCipher = null;
        //3. Establish connection with trusted
        try (Socket trustedSkt = new Socket(TRUSTED_IP, TRUSTED_PORT)) {
            //Connection variables
            ObjectOutputStream oos = new ObjectOutputStream(trustedSkt.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(trustedSkt.getInputStream());
            byte[] timestamp = generateTimestamp();

            //4. Encrypt clientID, serverID and timestamp using trusted's public key
            rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, trustedPubKey);
            byte[] encClientID = rsaCipher.doFinal(ownID.getBytes());
            byte[] encServerID = rsaCipher.doFinal(requestID.getBytes());
            byte[] encTimestamp = rsaCipher.doFinal(timestamp);

            //5. Craft request (clientID, serverID, timestamp)
            ArrayList<byte[]> request = new ArrayList<>();
            request.add(encClientID);
            request.add(encServerID);
            request.add(encTimestamp);

            //6. Send request to trusted
            oos.writeObject(request);

            //7. Receive reply (server's public key, signature, timestamp) from trusted
            ArrayList<byte[]> reply = (ArrayList<byte[]>) ois.readObject();

            //8. Decrypt timestamp using client's private key
            rsaCipher.init(Cipher.DECRYPT_MODE, ownPvtKey);
            byte[] recvTimestamp = rsaCipher.doFinal(reply.get(2));

            //9. Verify timestamp. Must be the same timestamp as the request crafted
            if (!Arrays.equals(timestamp, recvTimestamp)) {
                //10. If timestamp is not same, reply is not from trusted -> drop connection
                System.out.println("Timestamp received is different. Quitting the program.");
                return null;
            }

            //11. Retrive server's public key and signature
            byte[] serverPubKeyBytes = reply.get(0);
            byte[] signatureBytes = reply.get(1);

            //12. Verify the siganture using trusted's public key
            if (!verifySignature(trustedPubKey, serverPubKeyBytes, signatureBytes)) {
                //13. If signature does not match, public key corrupted. Drop connection
                System.out.println("Corrupted server public key. Quitting the program.");
                return null;
            }
            //14. Obtained legitimate server's public key. Close connection with trusted.
            KeyFactory kfRSA = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(serverPubKeyBytes);
            PublicKey requestPubKey = kfRSA.generatePublic(x509);
            return requestPubKey;
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | SignatureException | InvalidKeySpecException e) {
            //e.printStackTrace();
            System.out.println("Error. Connection with trusted unable to proceed.");
            return null;
        }
    }

    public static SecretKey getSessWithServer(Socket serverSkt, PublicKey serverPubKey, byte[] otp1, PrivateKey clientPvtKey, ObjectOutputStream oos, ObjectInputStream ois) {
        try {
            //1. Encrypt client's ownID + OTP1 using server's public key
            Cipher rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
            byte[] encClientID = rsaCipher.doFinal(CLIENT_ID.getBytes());
            byte[] encOTP1 = rsaCipher.doFinal(otp1);

            //2. Craft request & Send request to server 
            ArrayList<byte[]> request = new ArrayList<>();
            request.add(encClientID);
            request.add(encOTP1);
            oos.writeObject(request);
            

            //3. Receive encrypted reply (AES Session Key, OTP1, OTP2)
            ArrayList<byte[]> reply = (ArrayList<byte[]>) ois.readObject();
            

            //4. Decrypt received OTP1 using own private key
            rsaCipher.init(Cipher.DECRYPT_MODE, clientPvtKey);
            byte[] recOTP1 = rsaCipher.doFinal(reply.get(1));

            //5. Compare with OTP1
            if (!Arrays.equals(otp1, recOTP1)) {
                //5a. If it is not equal, reply attack, return null
                System.out.println("OTP1 does not match. Dropping connection with server");
                return null;
            }
            //6. Decrypt AES session key and OTP2 using own private key
            byte[] aesSessKeyBytes = rsaCipher.doFinal(reply.get(0));
            SecretKey aesKey = new SecretKeySpec(aesSessKeyBytes, "AES");
            byte[] otp2 = rsaCipher.doFinal(reply.get(2));

            //7. Encrypt OTP2 using AES key
            Cipher aesCipher = Cipher.getInstance(AES_ENC_ALGORITHM);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encOTP2 = aesCipher.doFinal(otp2);
            ArrayList<byte[]> ack = new ArrayList<>();
            ack.add(encOTP2);
            //8. Complete the handshake by sending reply back to server.
            oos.writeObject(ack);
            return aesKey;
            
        } catch (ClassNotFoundException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Unable to establish session with server.");
            //e.printStackTrace();
            return null;
        }
    }
}

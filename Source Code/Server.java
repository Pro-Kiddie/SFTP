/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author fwishyy
 */
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
import java.security.Key;
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
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class Server {

    //Class variables
    private static final String TRUSTED_PUB_KEY_FILE = "server/trusted.pub";
    private static final String SERVER_PUB_KEY_FILE = "server/server.pub";
    private static final String SERVER_PVT_KEY_FILE = "server/server.pfx";
    private static final String TRUSTED_IP = "127.0.0.1";
    private static final int TRUSTED_PORT = 16555;
    private static final String CLIENT_IP = "127.0.0.1";
    private static final int SERVER_PORT = 16666;
    private static final String RSA_ENC_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SERVER_ID = "server";
    private static final int AES_KEY_SIZE = 256;
    private static final String AES_ENC_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String HASHING_ALGORITHM = "SHA-256";
    private static final int SESSION_RENEWAL_LIMIT = 5; //Set at 5 for demonstration purpose

    public static void main(String[] args) {
        Path path = Paths.get(SERVER_PVT_KEY_FILE);
        PrivateKey serverPvtKey = null;
        PublicKey trustedPubKey = null;
        KeyFactory kfRSA = null;
        int imageCount = 0;
        try {
            //Load server private key
            byte[] serverPvtKeyBytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(serverPvtKeyBytes);
            kfRSA = KeyFactory.getInstance("RSA");
            serverPvtKey = kfRSA.generatePrivate(pkcs8);            
       
        } catch (IOException e) {
            System.out.println("Server's private key is not found.");
            System.exit(1);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error. Failed to start server. Corrupted server private key.");
            System.exit(1);
        }
        
        try {
            //Load trusted public key
            path = Paths.get(TRUSTED_PUB_KEY_FILE);
            byte[] trustedPubKeyBytes = Files.readAllBytes(path);
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(trustedPubKeyBytes);
            kfRSA = KeyFactory.getInstance("RSA");
            trustedPubKey = kfRSA.generatePublic(x509);
        } catch (IOException e) {
            System.out.println("Trusted's private key is not found.");
            System.exit(1);
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error. Failed to start server. Corrupted trusted private key.");
            System.exit(1);
        }
        
        //Establish connection with client
        while (true) {
            try (ServerSocket serverSocket = new ServerSocket(SERVER_PORT)) {
				System.out.println("Server ready to accept connection from client. Listening on Port: " + SERVER_PORT);
                while (true) {
                    try (Socket socket = serverSocket.accept()) {
						System.out.println("Accepted client connection from " + socket.getRemoteSocketAddress().toString());
                        while (true) {
							System.out.println("Establishing a new session with client.");
                            imageCount = 0;

                            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                            //4. Receive client's request which contains ClientID(Encrypted), OTP
                            System.out.println("Receiving request from client ...");
                            ArrayList<byte[]> request = (ArrayList<byte[]>) ois.readObject();
                            Cipher rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
                            rsaCipher.init(Cipher.DECRYPT_MODE, serverPvtKey);      
                            String CLIENT_ID = new String(rsaCipher.doFinal(request.get(0)));
                            
                            
                            System.out.println("Retrieving client public key ...");
                            PublicKey clientPubKey = getPubKeyFromTrusted(SERVER_ID, CLIENT_ID, 
                                    trustedPubKey, serverPvtKey);
                            System.out.println("Client public key retrieved and verified");

                            //Generate AES KEY
                            System.out.println("Sending reply which includes session key to client.");
                            KeyGenerator kg = KeyGenerator.getInstance("AES");
                            kg.init(AES_KEY_SIZE);
                            Key AESKEY = kg.generateKey();
                            byte[] AESBytes = AESKEY.getEncoded();
                            //Generate OTP 2
                            SecureRandom secureRandom = new SecureRandom();
                            byte[] OTP2 = new byte[8];
                            secureRandom.nextBytes(OTP2);
                            //decrypt OTP 1
                            byte[] OTP1 = request.get(1);
                            byte[] decryptedOTP1 = rsaCipher.doFinal(OTP1);
                            //adding to reply arraylist
                            rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
                            rsaCipher.init(Cipher.ENCRYPT_MODE, clientPubKey);

                            ArrayList<byte[]> reply = new ArrayList<>();
                            reply.add(rsaCipher.doFinal(AESBytes));
                            reply.add(rsaCipher.doFinal(decryptedOTP1));
                            reply.add(rsaCipher.doFinal(OTP2));

                            oos.writeObject(reply);
                            System.out.println("Done.");

                            //receive client acknowledgment
                            System.out.println("Waiting for client's acknowledgement to establish the session.");
                            ArrayList<byte[]> ack = (ArrayList<byte[]>) ois.readObject();
                            // Change to decrypt mode
                            Cipher AESCipher = Cipher.getInstance(AES_ENC_ALGORITHM);
                            AESCipher.init(Cipher.DECRYPT_MODE, AESKEY);

                            // Now decrypt the text
                            byte[] receivedOTP2 = AESCipher.doFinal(ack.get(0));

                            if (Arrays.equals(OTP2, receivedOTP2)) {
                                System.out.println("Session Established.");
                                System.out.println("Sending image to client using session key.");
                                AESCipher.init(Cipher.ENCRYPT_MODE, AESKEY);
                                MessageDigest hash = MessageDigest.getInstance(HASHING_ALGORITHM);
                                path = Paths.get("server/images/2018-03-22_231243.jpg");
                                byte[] imageData = Files.readAllBytes(path);
                                ArrayList<byte[]> imageReply = new ArrayList<>();
                                imageReply.add(AESCipher.doFinal(imageData));
                                imageReply.add(hash.digest(AESCipher.doFinal(imageData)));

                                oos.writeObject(imageReply);
                                imageCount++;
                                System.out.println("Done.");

                                while (true) {

                                    if (imageCount > SESSION_RENEWAL_LIMIT) {
										System.out.println("Session needs to be renewed. Signal session renewal.");
                                        ArrayList<byte[]> renewal_request = new ArrayList<byte[]>();
                                        AESCipher.init(Cipher.ENCRYPT_MODE, AESKEY);
                                        renewal_request.add(AESCipher.doFinal(decryptedOTP1));
                                        oos.writeObject(renewal_request);
                                        break;
                                    }

                                    Thread.sleep(5000);
                                    path = Paths.get("server/images/2018-03-22_231243.jpg");
                                    imageData = Files.readAllBytes(path);
                                    imageReply = new ArrayList<>();
                                    AESCipher.init(Cipher.ENCRYPT_MODE, AESKEY);
                                    imageReply.add(AESCipher.doFinal(imageData));
                                    imageReply.add(hash.digest(AESCipher.doFinal(imageData)));
                                    oos.writeObject(imageReply);
                                    imageCount++;

                                }

                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Connection with client closed. Back to listening state.");
                //e.printStackTrace();
            }
        }

    }

    public static byte[] generateTimestamp() {
        long now = System.currentTimeMillis();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(now);
        return buffer.array();
    }

    public static boolean verifySignature(PublicKey pubKey, byte[] data, byte[] signature) 
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature rsa256 = Signature.getInstance(SIGNATURE_ALGORITHM);
        rsa256.initVerify(pubKey);
        rsa256.update(data);
        return rsa256.verify(signature);
    }

    public static PublicKey getPubKeyFromTrusted(String ownID, String requestID, 
            PublicKey trustedPubKey, PrivateKey ownPvtKey) {
        //Method variables
        Cipher rsaCipher = null;
        //3. Establish connection with trusted
        try (Socket trustedSkt = new Socket(TRUSTED_IP, TRUSTED_PORT)) {
            //Connection variables
            ObjectOutputStream oos = new ObjectOutputStream(trustedSkt.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(trustedSkt.getInputStream());
            byte[] timestamp = generateTimestamp();

            //4. Encrypt ownID, requestID and timestamp using trusted's public key
            rsaCipher = Cipher.getInstance(RSA_ENC_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, trustedPubKey);
            byte[] encServerID = rsaCipher.doFinal(ownID.getBytes());
            byte[] encClientID = rsaCipher.doFinal(requestID.getBytes());
            byte[] encTimestamp = rsaCipher.doFinal(timestamp);

            //5. Craft request (serverID, clientID, timestamp)
            ArrayList<byte[]> request = new ArrayList<>();
            request.add(encServerID);
            request.add(encClientID);
            request.add(encTimestamp);

            //6. Send request to trusted
            oos.writeObject(request);

            //7. Receive reply (client's public key, signature, timestamp) from trusted
            ArrayList<byte[]> reply = (ArrayList<byte[]>) ois.readObject();

            //8. Decrypt timestamp using own private key
            rsaCipher.init(Cipher.DECRYPT_MODE, ownPvtKey);
            byte[] recvTimestamp = rsaCipher.doFinal(reply.get(2));

            //9. Verify timestamp. Must be the same timestamp as the request crafted
            if (!Arrays.equals(timestamp, recvTimestamp)) {
                //10. If timestamp is not same, reply is not from trusted -> drop connection
                System.out.println("Timestamp received is different. Quitting the program.");
                return null;
            }

            //11. Retrive client's public key and signature
            byte[] clientPubKeyBytes = reply.get(0);
            byte[] signatureBytes = reply.get(1);

            //12. Verify the siganture using trusted's public key
            if (!verifySignature(trustedPubKey, clientPubKeyBytes, signatureBytes)) {
                //13. If signature does not match, public key corrupted. Drop connection
                System.out.println("Corrupted client public key. Quitting the program.");
                return null;
            }
            //14. Obtained legitimate client's public key. Close connection with trusted.
            KeyFactory kfRSA = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(clientPubKeyBytes);
            PublicKey requestPubKey = kfRSA.generatePublic(x509);
            System.out.println("Retrieved legitimate public key of " + requestID + " from trusted.");
            return requestPubKey;
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException 
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException 
                | ClassNotFoundException | SignatureException | InvalidKeySpecException e) {
            //e.printStackTrace();
            System.out.println("Error. Connection with trusted unable to proceed.");
            return null;
        }
    }
}

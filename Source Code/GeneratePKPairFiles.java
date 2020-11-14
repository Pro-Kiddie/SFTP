
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author yang_
 */
public class GeneratePKPairFiles {
    public static void main(String[] args) {
        
        if (args.length != 1){
            System.out.println("Usage: ./GeneratePKPairFiles ClientID/ServerID");
            System.exit(0);
        }
        String id = args[0];
        try{
            //Generate RSA key pair for the client or server
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            kg.initialize(2048);
            KeyPair keyPair = kg.genKeyPair();
            Key publicKey = keyPair.getPublic();
            Key privateKey = keyPair.getPrivate();
            System.out.println("Successfully generated key pair.");
            System.out.println("Saving the key pair into files.");
            
            //Save the key pair into files with ID.pub and ID.pfx
            FileOutputStream publicFile = new FileOutputStream(id + ".pub");
            FileOutputStream privateFile = new FileOutputStream(id + ".pfx");
            publicFile.write(publicKey.getEncoded());
            privateFile.write(privateKey.getEncoded());
            publicFile.close();
            privateFile.close();
            
            System.out.println("Successfully saved key pair into files");
            System.out.println("Public Key Format: " + publicKey.getFormat());
            System.out.println("Private Key Format: " + privateKey.getFormat());
        }catch (NoSuchAlgorithmException | IOException e){
            System.out.println("Error. Failed to generate Public Key pair files for " + args[0]);
            System.exit(0);
        }
         
        
    }
}

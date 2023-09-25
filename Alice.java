/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.*;
import java.net.*;

/**
 *
 * @author karankarwal
 */
public class Alice {
    public static void main(String[] args) throws IOException, RuntimeException {



        String hostName = "localhost";
        int portNumber = 4444;

        try (
                Socket kkSocket = new Socket(hostName, portNumber);
                PrintWriter output= new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader input = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ) {
            BufferedReader stdIn =
                    new BufferedReader(new InputStreamReader(System.in));

            RSAProtocol vc = new RSAProtocol();
            SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
            vc.initFromStrings();
            String NA = "NonceA";
            //send Id to KDC
            output.println("Alice");
            System.out.println("Sent Id to KDC");

            //receive encrypted message from KDC
            String encMess = input.readLine();
            System.out.println("Received encrypted message 1 from KDC : " + encMess);
            vc.decryptAPriv(encMess);
            System.out.println("Decrypted message 1 from KDC: " + vc.decryptAPriv(encMess));
            //Split decrypted message into NK1 and IDK
            String[] parts = vc.decryptAPriv(encMess).split(" ");
            String NK1 = parts[0];
            String IDK = parts[1];

            //send encrypted message to KDC
            String encMess2 = vc.encryptKDCPub(NA + " " + NK1);
            System.out.println("Sending encrypted message 2 to KDC: " + encMess2);
            output.println(encMess2);

            //receive encrypted message from KDC
            String encMess3 = input.readLine();
            System.out.println("Received encrypted message 3 from KDC : " + encMess3);
            vc.decryptAPriv(encMess3);
            System.out.println("Decrypted message 3 from KDC: " + vc.decryptAPriv(encMess3));

            //receive encrypted message from KDC
            String encMess4 = input.readLine();
            System.out.println("Received encrypted message 4 from KDC : " + encMess4);
            vc.decryptKDCPub(encMess4);
            System.out.println("Decrypted message 4 from KDC, KA: " + vc.decryptKDCPub(encMess4));
            String KA = vc.decryptKDCPub(encMess4);

            //take user input
            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                System.out.println("Would you like to send Alice and Bob's ID's to the server? (Y/N)");
                if (userInput.equals("Y")) {
                    output.println("Alice Bob");
                    System.out.println("Sent Alice and Bob's ID's to the server");
                    break;
                } else if (userInput.equals("N")) {
                    System.out.println("Exiting...");
                    System.exit(0);
                } else {
                    System.out.println("Invalid input. Please try again.");
                }
            }

            //receive AES encrypted message from KDC
            String encMess5 = input.readLine();
            System.out.println("Received encrypted message 5 from KDC : " + encMess5);
            String lastMess = aes.decrypt(encMess5, KA.getBytes());
            System.out.println("Decrypted message 5 from KDC, KAB: " + lastMess);
            String[] parts2 = lastMess.split(" ");
            String sessionKey = parts2[0];
            String Aid = parts2[1];
            System.out.println("Decrypted message 5 from KDC, session key with Alice: " + sessionKey);


            System.out.println("What Message would you like to send to the Chat room?");
            //take user input
            while ((userInput = input.readLine()) != null) {
                String lastLine = "Alice " + userInput;
                String encMess6 = aes.encrypt(lastLine, KA.getBytes());
                System.out.println("Sending encrypted message 6 to KDC, then other Clients: " + encMess6);
                output.println(encMess6);
                vc.signAPriv(lastLine);
                System.out.println("Sending signed message 7 to KDC, then other Clients: " + vc.signAPriv(lastLine));
                output.println(vc.signAPriv(lastLine));
                System.out.println("What Message would you like to send to the Chat room?");
            }



        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}


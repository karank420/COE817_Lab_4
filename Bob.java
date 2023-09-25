import java.io.*;
import java.net.*;

public class Bob {
    public static void main(String[] args) throws IOException, RuntimeException {



        String hostName = "localhost";
        int portNumber = 4444;

        try (
                Socket kkSocket = new Socket(hostName, portNumber);
                PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ) {
            BufferedReader stdIn =
                    new BufferedReader(new InputStreamReader(System.in));

            RSAProtocol vc = new RSAProtocol();
            vc.initFromStrings();
            String NB = "NonceB";
            //send Id to KDC
            out.println("Bob");
            System.out.println("Sent Id to KDC");

            //receive encrypted message from KDC
            String encMess = in.readLine();
            System.out.println("Received encrypted message 1 from KDC : " + encMess);
            vc.decryptBPriv(encMess);
            System.out.println("Decrypted message 1 from KDC: " + vc.decryptBPriv(encMess));
            //Split decrypted message into NK1 and IDK
            String[] parts = vc.decryptBPriv(encMess).split(" ");
            String NK2 = parts[0];
            String IDK = parts[1];

            //send encrypted message to KDC
            String encMess2 = vc.encryptKDCPub(NB + " " + NK2);
            System.out.println("Sending encrypted message 2 to KDC: " + encMess2);
            out.println(encMess2);

            //receive encrypted message from KDC
            String encMess3 = in.readLine();
            System.out.println("Received encrypted message 3 from KDC : " + encMess3);
            vc.decryptBPriv(encMess3);
            System.out.println("Decrypted message 3 from KDC: " + vc.decryptBPriv(encMess3));

            //receive encrypted message from KDC
            String encMess4 = in.readLine();
            System.out.println("Received encrypted message 4 from KDC : " + encMess4);
            vc.decryptKDCPub(encMess4);
            System.out.println("Decrypted message 4 from KDC, KA: " + vc.decryptKDCPub(encMess4));
            String KA = vc.decryptKDCPub(encMess4);

            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                System.out.println("Would you like oyur session key with Alice? (Y/N)");
                if (userInput.equals("Y")) {
                    break;
                } else if (userInput.equals("N")) {
                    System.out.println("Exiting...");
                    System.exit(0);
                } else {
                    System.out.println("Invalid input. Please try again.");
                }
            }

            //receive AES encrypted message from KDC
            String encMess5 = in.readLine();
            System.out.println("Received encrypted message 5 from KDC : " + encMess5);
            SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
            String lastMess = aes.decrypt(encMess5, KA.getBytes());
            System.out.println("Decrypted message 5 from KDC : " + lastMess);
            //split last mess into session key and Aid
            String[] parts2 = lastMess.split(" ");
            String sessionKey = parts2[0];
            String Aid = parts2[1];
            System.out.println("Decrypted message 5 from KDC, session key with Alice: " + sessionKey);



            //while loop that receieves messages from Alice

            while ((userInput = stdIn.readLine()) != null) {
                System.out.println("Would you like to receive a message? (Y/N)");
                if (userInput.equals("Y")) {

                    String encMess6 = in.readLine();
                    System.out.println("Received encrypted message 6 from Alice : " + encMess6);

                } else if (userInput.equals("N")) {
                    System.out.println("Exiting...");
                    System.exit(0);
                } else {
                    System.out.println("Invalid input. Please try again.");
                }



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

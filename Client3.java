import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class Client3 {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 5000)){
            //reading the input from server
            BufferedReader input = new BufferedReader( new InputStreamReader(socket.getInputStream()));

            //returning the output to the server : true statement is to flush the buffer otherwise
            //we have to do it manuallyy
            PrintWriter output = new PrintWriter(socket.getOutputStream(),true);

            //taking the user input
            Scanner scanner = new Scanner(System.in);
            String userInput;
            String response;
            String clientName = "empty";

            RSAProtocol vc = new RSAProtocol();
            vc.initFromStrings();
            String NC = "NonceC";
            //send Id to KDC
            output.println("Charlie");
            System.out.println("Sent Id to KDC");

            //receive encrypted message from KDC
            String encMess = input.readLine();
            System.out.println("Received encrypted message 1 from KDC : " + encMess);
            vc.decryptCPriv(encMess);
            System.out.println("Decrypted message 1 from KDC: " + vc.decryptCPriv(encMess));
            //Split decrypted message into NK2 and IDK
            String[] parts = vc.decryptCPriv(encMess).split(" ");
            String NK2 = parts[0];
            String IDK = parts[1];

            //send encrypted message 2 to KDC
            String encMess2 = vc.encryptKDCPub(NC + " " + NK2);
            System.out.println("Sending encrypted message 2 to KDC: " + encMess2);
            output.println(encMess2);

            //receive encrypted message 3 from KDC
            String encMess3 = input.readLine();
            System.out.println("Received encrypted message 3 from KDC : " + encMess3);
            vc.decryptCPriv(encMess3);
            System.out.println("Decrypted message 3 from KDC: " + vc.decryptCPriv(encMess3));

            //receive encrypted message 4 from KDC
            String encMess4 = input.readLine();
            System.out.println("Received encrypted message 4 from KDC : " + encMess4);
            vc.decryptKDCPub(encMess4);
            System.out.println("Decrypted message 4 from KDC, KA: " + vc.decryptKDCPub(encMess4));
            String KA = vc.decryptKDCPub(encMess4);


            //receive AES encrypted message from KDC
            String encMess5 = input.readLine();
            System.out.println("Received encrypted message 5 from KDC : " + encMess5);
            SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
            String lastMess = aes.decrypt(encMess5, KA.getBytes());
            System.out.println("Decrypted message 5 from KDC : " + lastMess);
            //split last mess into session key and Aid
            String[] parts2 = lastMess.split(" ");
            String sessionKey = parts2[0];
            String Aid = parts2[1];
            System.out.println("Decrypted message 5 from KDC, session key with Alice: " + sessionKey);

            ClientRunnable3 clientRun = new ClientRunnable3(socket);


            new Thread(clientRun).start();
            //loop closes when user enters exit command

            do {

                if (clientName.equals("empty")) {
                    System.out.println("Enter your name ");
                    userInput = scanner.nextLine();
                    clientName = userInput;
                    output.println(userInput);
                    if (userInput.equals("exit")) {
                        break;
                    }
                }
                else {
                    String message = ( "(" + clientName + ")" + " message:" );
                    System.out.println(message);
                    userInput = scanner.nextLine();
                    String signedMessage = vc.signCPriv(userInput);
                    String encryptedMessage = aes.encrypt(userInput, KA.getBytes());
                    output.println(message + " " + signedMessage + " " + encryptedMessage);
                    if (userInput.equals("exit")) {
                        //reading the input from server
                        break;
                    }
                }

            } while (!userInput.equals("exit"));




        } catch (Exception e) {
            System.out.println("Exception occured in client main: " + e.getStackTrace());
        }
    }
}

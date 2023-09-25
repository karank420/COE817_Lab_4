import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;


public class ServerThread extends Thread {
    private Socket socket;
    private ArrayList<ServerThread> threadList;
    private PrintWriter output;

    public ServerThread(Socket socket, ArrayList<ServerThread> threads) {
        this.socket = socket;
        this.threadList = threads;
    }

    @Override
    public void run() {
        try {
            //Reading the input from Client
            BufferedReader input = new BufferedReader( new InputStreamReader(socket.getInputStream()));

            //returning the output to the client : true statement is to flush the buffer otherwise
            //we have to do it manuallyy
            output = new PrintWriter(socket.getOutputStream(),true);

            System.out.println("Connected to client.");
            RSAProtocol vc = new RSAProtocol();
            SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
            vc.initFromStrings();
            String NK1 = "NonceK1";
            String NK2 = "NonceK2";
            String IDK = "KDC";
            String KA = "MZygpewJsCpRrfOr";
            String KAB = "ABSymmetricKey";

            //receive Id from client
            String ID = input.readLine();

            //If Id is Alice, send encrypted message with NK1 and IDK
            if (ID.equals("Alice")) {

                System.out.println("Received Id from client : " + ID);
                String encMess = vc.encryptAPub(NK1 + " " + IDK);
                System.out.println("Sending encrypted message 1 to Alice: " + encMess);
                output.println(encMess);

                //receive encrypted message from Alice
                String encMess2 = input.readLine();
                System.out.println("Received encrypted message 2 from Alice: " + encMess2);
                vc.decryptKDCPriv(encMess2);
                System.out.println("Decrypted message 2 from Alice: " + vc.decryptKDCPriv(encMess2));
                //Split decrypted message into NA and NK1
                String[] parts = vc.decryptKDCPriv(encMess2).split(" ");
                String NA = parts[0];


                //send encrypted message to Alice
                String encMess3 = vc.encryptAPub(NK1);
                System.out.println("Sending encrypted message 3 to Alice: " + encMess3);
                output.println(encMess3);

                //Send encrypted message to Alice
                String encMess4 = vc.encryptKDCPriv(KA);
                System.out.println("Sending encrypted message 4 to Alice: " + encMess4);
                output.println(encMess4);

                //Receive message from Alice
                ID = input.readLine();
                System.out.println("Received IDs' from Alice: " + ID);

                //

                //if message is Alice and Bob's ID, Send encrypted message to Alice and Bob
                if (ID.equals("Alice Bob")) {
                    String encMess5 = aes.encrypt(KAB + " " + "Bob", KA.getBytes());
                    System.out.println("Sending encrypted message 5 to Alice: " + encMess5);
                    output.println(encMess5);
                }


            } else if (ID.equals("Bob")) {
                System.out.println("Received Id from client : " + ID);
                String encMess = vc.encryptBPub(NK2 + " " + IDK);
                System.out.println("Sending encrypted message 1 to Bob: " + encMess);
                output.println(encMess);

                //receive encrypted message from Bob
                String encMess2 = input.readLine();
                System.out.println("Received encrypted message 2 from Bob: " + encMess2);
                vc.decryptKDCPriv(encMess2);
                System.out.println("Decrypted message 2 from Bob: " + vc.decryptKDCPriv(encMess2));
                //Split decrypted message into NB and NK2
                String[] parts = vc.decryptKDCPriv(encMess2).split(" ");
                String NB = parts[0];

                //send encrypted message to Bob
                String encMess3 = vc.encryptBPub(NK2);
                System.out.println("Sending encrypted message 3 to Bob: " + encMess3);
                output.println(encMess3);

                //Send encrypted message to Bob
                String encMess4 = vc.encryptKDCPriv(KA); //come back to later
                System.out.println("Sending encrypted message 4 to Bob: " + encMess4);
                output.println(encMess4);

                //Send AES encrypted message to Bob
                String encMess5 = aes.encrypt(KAB + " " + "Alice", KA.getBytes());
                System.out.println("Sending encrypted message 5 to Bob: " + encMess5);
                output.println(encMess5);

            } else if (ID.equals("Charlie")) {
                System.out.println("Received Id from client : " + ID);
                String encMess = vc.encryptCPub(NK2 + " " + IDK);
                System.out.println("Sending encrypted message 1 to Charlie: " + encMess);
                output.println(encMess);

                //receive encrypted message from Charlie
                String encMess2 = input.readLine();
                System.out.println("Received encrypted message 2 from Charlie: " + encMess2);
                vc.decryptKDCPriv(encMess2);
                System.out.println("Decrypted message 2 from Charlie: " + vc.decryptKDCPriv(encMess2));
                //Split decrypted message into NB and NK2
                String[] parts = vc.decryptKDCPriv(encMess2).split(" ");
                String NC = parts[0];

                //Send encrypted message to Charlie
                String encMess3 = vc.encryptCPub(NK2);
                System.out.println("Sending encrypted message 3 to Charlie: " + encMess3);
                output.println(encMess3);

                //Send encrypted message to Charlie
                String encMess4 = vc.encryptKDCPriv(KA); //come back to later
                System.out.println("Sending encrypted message 4 to Charlie: " + encMess4);
                output.println(encMess4);

                //Send AES encrypted message to Charlie
                String encMess5 = aes.encrypt(KAB + " " + "Alice", KA.getBytes());
                System.out.println("Sending encrypted message 5 to Charlie: " + encMess5);
                output.println(encMess5);

            }

            //inifite loop for server
            while(true) {
                String outputString = input.readLine();
                //if user types exit command
                if(outputString.equals("exit")) {
                    break;
                }
                printToALlClients(outputString);
                //output.println("Server says " + outputString);
                System.out.println("Server received " + outputString);

            }


        } catch (Exception e) {
            System.out.println("Error occured " +e.getStackTrace());
        }
    }

    private void printToALlClients(String outputString) {
        for( ServerThread sT: threadList) {
            sT.output.println(outputString);
        }

    }
}

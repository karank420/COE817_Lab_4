import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientRunnable3 implements Runnable {

    private Socket socket;
    private BufferedReader input;
    // private PrintWriter output;
    private static final byte[] KEY = "MZygpewJsCpRrfOr".getBytes();
    SymmetricKeyAuthentication aes = new SymmetricKeyAuthentication();
    RSAProtocol vc = new RSAProtocol();


    public ClientRunnable3(Socket s) throws IOException {
        this.socket = s;
        this.input = new BufferedReader( new InputStreamReader(socket.getInputStream()));
        // this.output = new PrintWriter(socket.getOutputStream(),true);
    }
    @Override
    public void run() {
        vc.initFromStrings();
        try {
            while(true) {
                String response = input.readLine();
                String[] parts = response.split(" ");
                String id = parts[0];

                if (id.equals("(Alice)")){
                    String signature = parts[2];
                    String encmessage = parts[3];
                    String decmess;
                    decmess = aes.decrypt(encmessage, KEY);
                    System.out.println(response);
                    System.out.println("Decrypted message from Alice: " + decmess);
                    System.out.println("Signature from Alice: " + vc.verifyAPub(decmess, signature));
                }
                else if (id.equals("(Bob)")){
                    String signature = parts[2];
                    String encmessage = parts[3];
                    String decmess;
                    decmess = aes.decrypt(encmessage, KEY);
                    System.out.println(response);
                    System.out.println("Decrypted message from Bob: " + decmess);
                    System.out.println("Signature from Bob: " + vc.verifyBPub(decmess, signature));
                }
                /*else if (id.equals("(Charlie)")){
                    String signature = parts[2];
                    String encmessage = parts[3];
                    String decmess;
                    decmess = aes.decrypt(encmessage, KEY);
                    System.out.println(response);
                    System.out.println("Decrypted message from Charlie: " + decmess);
                    System.out.println("Signature from Charlie: " + vc.verifyCPub(decmess, signature));
                }*/


            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                input.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}

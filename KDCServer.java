import java.io.*;
import java.net.*;
import java.util.ArrayList;
/**
 *
 * @author karankarwal
 */
public class KDCServer {

    public static void main(String[] args) throws IOException {
        int portNumber = 4444;



        boolean listening = true;
        ArrayList<KDCMultiServerThread> threadList = new ArrayList<>();
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            while (listening) {
                System.out.println("Listening on port " + portNumber);
                Socket socket = serverSocket.accept();
                KDCMultiServerThread KDCMultiServerThread = new KDCMultiServerThread(socket, threadList);
                threadList.add(KDCMultiServerThread);
                KDCMultiServerThread.start();

            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
    }

}
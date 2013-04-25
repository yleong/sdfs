package sdfs;

import java.io.IOException;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Main {
  public static void main(String[] args) {
//    int port = Integer.parseInt(args[0]);
    int port = 3000;
    try {
      System.out.println("Locating server socket factory for SSL...");
      SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

      System.out.println("Creating a server socket on port " + port);
      SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);

      String[] suites = serverSocket.getSupportedCipherSuites();
      System.out.println("Support cipher suites are:");
      for (int i = 0; i < suites.length; i++) {
        System.out.println(suites[i]);
      }
      serverSocket.setEnabledCipherSuites(suites);

      System.out.println("Support protocols are:");
      String[] protocols = serverSocket.getSupportedProtocols();
      for (int i = 0; i < protocols.length; i++) {
        System.out.println(protocols[i]);
      }

      System.out.println("Waiting for client...");
      SSLSocket socket = (SSLSocket) serverSocket.accept();

      System.out.println("Starting handshake...");
      socket.startHandshake();

      System.out.println("Just connected to " + socket.getRemoteSocketAddress());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
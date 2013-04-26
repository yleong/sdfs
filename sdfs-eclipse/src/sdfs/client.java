package sdfs;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class client {

	public void Start_FS_session(){
		
	}
	
	public void GetFile(String UID){
		
	}
	
	public void PutFile(String UID){
		
	}
	
	public void make_connection(){
	    int port = 3000;
		    try {
		      System.out.println("Locating server socket factory for SSL...");
		      SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

		      System.out.println("Creating a server socket on port " + port);
		      SSLSocket Socket = (SSLSocket) factory.createSocket("143.215.116.52",port);

		      String[] suites = Socket.getSupportedCipherSuites();
		      System.out.println("Support cipher suites are:");
		      for (int i = 0; i < suites.length; i++) {
		        System.out.println(suites[i]);
		      }
		      Socket.setEnabledCipherSuites(suites);

		      System.out.println("Support protocols are:");
		      String[] protocols = Socket.getSupportedProtocols();
		      for (int i = 0; i < protocols.length; i++) {
		        System.out.println(protocols[i]);
		      }

		      System.out.println("Waiting for client...");
//		      SSLSocket socket = (SSLSocket) Socket.sta

		      System.out.println("Starting handshake...");
		      Socket.startHandshake();
		      BufferedWriter w = new BufferedWriter(
		              new OutputStreamWriter(Socket.getOutputStream()));
		      w.write("hello");
		      w.flush();
		      w.close();
		      
		      System.out.println("Just connected to " + Socket.getRemoteSocketAddress());
		      
		      Socket.close();
		    } catch (IOException e) {
		      e.printStackTrace();
		    }
	}
}

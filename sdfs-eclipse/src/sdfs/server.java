package sdfs;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class server {

	public void listen(){
		int port = 3000;
		try {
			System.out.println("Locating server socket factory for SSL...");
			String ksName = "/Users/arvindersaini/Desktop/CS-6238/keystore.jks";
			char ksPass[] = "cs6238-ca".toCharArray();
			char ctPass[] = "cs6238-ca".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);

			KeyManagerFactory kmf = 
					KeyManagerFactory.getInstance("SunX509");

			kmf.init(ks, ctPass);
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(kmf.getKeyManagers(), null, null);
			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);
			printServerSocketInfo(serverSocket);


			//		    --------------------
			//			SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

			//			System.out.println("Creating a server socket on port " + port);
			//			SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);

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
			BufferedReader r = new BufferedReader(
					new InputStreamReader(socket.getInputStream()));

			System.out.println(r.readLine());

			System.out.println("Just connected to " + socket.getRemoteSocketAddress());
			r.close();
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void printServerSocketInfo(SSLServerSocket s) {
		System.out.println("Server socket class: "+s.getClass());
		System.out.println("   Socker address = "
				+s.getInetAddress().toString());
		System.out.println("   Socker port = "
				+s.getLocalPort());
		System.out.println("   Need client authentication = "
				+s.getNeedClientAuth());
		System.out.println("   Want client authentication = "
				+s.getWantClientAuth());
		System.out.println("   Use client mode = "
				+s.getUseClientMode());
	} 


	public void handler(){

	}

	public void check_owner(){

	}

	public void sendFile_client(){

	}

	public void check_file_existence(){

	}
}

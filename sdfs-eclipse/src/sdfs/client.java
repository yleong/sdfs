package sdfs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class client {
	private SSLSocket Socket;
	private String fileName;
	private BufferedWriter bufferedWriter = null;

	//This method is requests a file from the server
	//based on the user provided filename
	public void GetFile(String UID){
		fileName = UID;
		String localfileName = "../ClientFile/" + fileName;
		BufferedWriter w;
		try {
			w = new BufferedWriter(
					new OutputStreamWriter(Socket.getOutputStream()));
			w.write("g");
			int fileNameSize = fileName.length();

			ByteBuffer filename_size = ByteBuffer.allocate(4);
			filename_size.putInt(fileNameSize);
			char[] char_fileName = new String(filename_size.array()).toCharArray();
			w.write(char_fileName,0,4);
			w.write(fileName);
			w.flush();


			BufferedReader r = new BufferedReader(
					new InputStreamReader(Socket.getInputStream()));
			create_File(localfileName, r);
			w.close();

		}catch(FileNotFoundException fe){
			System.out.println("File not found ");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	//This method saves the file on the client side.
	public void create_File(String file_name, BufferedReader br){
		try {
			ByteBuffer file_size = ByteBuffer.allocate(8);
			// creates buffer
			char[] cbuf = new char[8];
			br.read(cbuf, 0, 8);
			for(int i=0; i<8 ;i++){
				System.out.println((int)cbuf[i]);
			}
			

			for (char c:cbuf)
			{
				file_size.put((byte) c);
			}
			file_size.rewind();
			long int_size = file_size.getLong();

			StringBuffer fileData = new StringBuffer();
			System.out.println(int_size);
			for(long i=0; i< int_size ; i++){
				fileData.append((char) br.read());
			}
			System.out.println(fileData.toString());
			
			//Assume default encoding.
			FileWriter fileWriter = new FileWriter(file_name);

			// Always wrap FileWriter in BufferedWriter.
			bufferedWriter = new BufferedWriter(fileWriter);

			// Note that write() does not automatically
			// append a newline character.
			bufferedWriter.write(fileData.toString());

			// Always close files.
			bufferedWriter.close();


		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
	}



	//This method tries to read a file and
	//send it over the server
	public void PutFile(String UID){

		fileName = UID;					//need to see how the filename and Id are related
		String localFileName = "../ClientFile/" + fileName;
		System.out.println(localFileName);
		BufferedWriter w;
		try {
			w = new BufferedWriter(
					new OutputStreamWriter(Socket.getOutputStream()));
			w.write("p");
			int fileNameSize = fileName.length();

			ByteBuffer filename_size = ByteBuffer.allocate(4);
			filename_size.putInt(fileNameSize);
			char[] char_fileName = new String(filename_size.array()).toCharArray();
			w.write(char_fileName,0,4);
			w.write(fileName);

			File file = new File(localFileName);
			FileInputStream fis = new FileInputStream(file);
			long fileSize = fis.available();
			ByteBuffer file_size = ByteBuffer.allocate(8);
			file_size.putInt((int)fileSize);
			char[] char_file = new String(file_size.array()).toCharArray();
			w.write(char_file,0,8);

			byte[] b = new byte[fis.available()];
			fis.read(b);
			String text = new String(b);
			w.write(text);

			//				w.write(fis.available());
			//				byte[] b = new byte[fis.available()];
			//				w.write(b, 0, len);
			//				fis.read(b);
			//				String text = new String(b);
			//				
			//				w.write(text);
			w.flush();
			w.close();
		}
		catch(FileNotFoundException fe){
			System.out.println("File not found ");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	//This method starts a new session with the server.
	public void Start_FS_session(){
		int port = 3000;
		try {
			// Use the public key from the AIDAP server as the trust store for this client.
			//   (note: created this keystore using InstallCerts.java from sun.com)
			Properties systemProps = System.getProperties();
			systemProps.put( "javax.net.ssl.trustStore", "../CS-6238/myTrustStore");
			System.setProperties(systemProps);

			System.out.println("Locating server socket factory for SSL...");
			String ksName = "../CS-6238/keystore.jks";
			char ksPass[] = "cs6238-ca".toCharArray();
			char ctPass[] = "cs6238-ca".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);

			KeyManagerFactory kmf = 
					KeyManagerFactory.getInstance("SunX509");

			kmf.init(ks, ctPass);
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(kmf.getKeyManagers(), null, null);
			SSLSocketFactory ssf = sc.getSocketFactory();
			//				SSLSocket Socket = (SSLSocket) ssf.createSocket("127.0.0.1",port);
			Socket = (SSLSocket) ssf.createSocket("127.0.0.1",port);
			//		    ---------------------
			System.out.println("Locating server socket factory for SSL...");
			//		      SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

			System.out.println("Creating a server socket on port " + port);
			//		      SSLSocket Socket = (SSLSocket) factory.createSocket("143.215.116.52",port);

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
			//		      BufferedWriter w = new BufferedWriter(
			//		              new OutputStreamWriter(Socket.getOutputStream()));
			//		      w.write("hello");
			//		      w.flush();
			//		      w.close();

			System.out.println("Just connected to " + Socket.getRemoteSocketAddress());

			//		      Socket.close();
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
}

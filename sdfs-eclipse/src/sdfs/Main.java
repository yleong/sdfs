package sdfs;

import java.util.Scanner;

public class Main {
	
	public static void main(String[] args) {
		Scanner reader = new Scanner(System.in);
		System.out.println("Enter input");
		//get user input for a
		String input = reader.next();
		
//		String mode = args[0];
		if(input.equals("server")){
			server obj_server = new server();
			obj_server.listen();
		}
		else if(input.equals("client")){
			client obj_client = new client();
			
			obj_client.Start_FS_session();			//starting the session with the server
			
			Scanner reader2 = new Scanner(System.in);	//asking user to enter the mode. put/get
			System.out.println("Enter mode and Id");
			//get user input for a
			String input2 = reader2.next();
			String UID = reader2.next();
			
			if(input2.equals("put")){
				obj_client.PutFile(UID);
			}
			else if(input2.equals("get")){
				obj_client.GetFile(UID);
			}
			else if(input2.equals("del")){
				Scanner readDelegateInfo = new Scanner(System.in);	//asking user to enter the mode. put/get
				System.out.println("Please enter file the following. \n File name \nRecepient name \nRights \nNumber of days \nPropagatable.");
				System.out.println("File name");
				String FileName = readDelegateInfo.next();
				System.out.println("Recepient");
				String Recepient = readDelegateInfo.next();
				System.out.println("Rights");
				String Rights = readDelegateInfo.next();
				System.out.println("Duration");
				String Duration = readDelegateInfo.next();
				System.out.println("Is it propagatable?");
				String Propagateable = readDelegateInfo.next();
			}
			else
				System.out.println("Invalid input");
		}
		else
			System.out.println("Invalid input");
	}
}
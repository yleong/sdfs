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
		else{
			client obj_client = new client();
			obj_client.Start_FS_session();
		}
	}
}
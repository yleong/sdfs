package sdfs;

public class DelegationToken implements java.io.Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -8470093355687010538L;
	private String fileName;
	private String recipientName;
	private String rights;
	private int numdays; //number of seconds before expiry
	private boolean propagate;

	DelegationToken(){} //empty constructor
	DelegationToken(String fileName, String recipientName, String rights, int numdays, boolean propagate){
		this.fileName = fileName;
	    this.recipientName = recipientName;
	    this.rights = rights;
	    this.numdays = numdays;
	    this.propagate = propagate;	    
	}

	
}

package sdfs;

public class DelegationToken implements java.io.Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -8470093355687010538L;
	public String fileName;
	public String recipientName;
	public String rights;
	public int numdays; //number of seconds before expiry
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

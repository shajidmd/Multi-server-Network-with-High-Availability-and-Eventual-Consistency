package activitystreamer.server;

public class LockItem {
	private String userName;
	// if one server send lock_request originally, then this var store the client connection
	// otherwise store the receive server connection
	private Connection originCon; 
	private Integer	   outConNumber;
	
	public LockItem(String name, Connection con, Integer outNum) {
		userName = name;
		originCon = con; 
		outConNumber = outNum;
	}
	
	public String getUserName() {
		return userName;
	}
	
	public Connection getOriginCon() {
		return originCon;
	}
	
	public boolean replyOrginCon () {
		outConNumber --;
		return outConNumber == 0;
	}
}

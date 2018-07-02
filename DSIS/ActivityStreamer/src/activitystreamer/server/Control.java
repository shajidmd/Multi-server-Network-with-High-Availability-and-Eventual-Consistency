package activitystreamer.server;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static boolean term = false;
	private static Listener listener;
	private static JSONParser parser; 
	private static ArrayList<JSONObject> announcementInfo; 
	private static String uniqueID; //the ID of current server
	private static ArrayList<LockItem> lockItemArray; // add by  the items handling the lock request
	private static JSONObject keyGenTripletAssociation;
	private static JSONObject keySecretPairs;
	private static List<MessageQueue> incomingActivityObjectQueue;
	private static List<MessageQueue> outgoingActivityObjectQueue;
	private static List<String> activeUsers;
	protected static Control control = null;

	public static Control getInstance() {
		if (control == null) {
			control = new Control();
		}
		return control;
	}

	public Control() {
		// initialize the connections array
		connections = new ArrayList<Connection>();
		announcementInfo = new ArrayList<JSONObject>();
		lockItemArray = new ArrayList<LockItem>();
		keyGenTripletAssociation = new JSONObject();
		keySecretPairs = new JSONObject();
		keySecretPairs.put("anonymous", "");
		keyGenTripletAssociation.put("ano", keySecretPairs);
		incomingActivityObjectQueue = new ArrayList<MessageQueue>();
		outgoingActivityObjectQueue = new ArrayList<MessageQueue>();
		activeUsers = new ArrayList<String>();
		// start a listener
		try {
			listener = new Listener();
			// add by 
			// initialise parser and remote connection
			parser = new JSONParser();
			initiateConnection();
			uniqueID = Settings.nextSecret();
			// end

			start(); // start regular operation
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: " + e1);
			System.exit(-1);
		}
	}

	public void initiateConnection() {
		// make a connection to another server if remote hostname is supplied
		if (Settings.getRemoteHostname() != null) {
			try {
				Connection newCon = outgoingConnection(
						new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
				newCon.setIsServer(true);
				// send authentication to the parent server
				authenticateRequest(newCon);
			} catch (IOException e) {
				log.error("failed to make connection to " + Settings.getRemoteHostname() + ":"
						+ Settings.getRemotePort() + " :" + e);
				System.exit(-1);
			}
		}
	}

	
	public synchronized Long findOpenPortsOnCurrentHostInterfaces() throws IOException {
	    try (
	        ServerSocket socket = new ServerSocket(0);
	    ) {
	      return (long) socket.getLocalPort();
	    }
	  }
	
	/*
	 * Processing incoming messages from the connection. Return true if the
	 * connection should close. add json parsing operation
	 */
	public synchronized boolean process(Connection con, String msg) {
		log.debug(msg);

		String command = "";
		JSONObject msgObject;
		try {
			msgObject = (JSONObject) parser.parse(msg);
			command = (String) msgObject.get("command");

			if (command == null) {
				command = "";
			}
		} catch (Exception e) {
			e.printStackTrace();
			responseInvalidMsg("Message parse error", con);
			return true;
		}

		switch (command) {
		case "AUTHENTICATE":
			return authentication(con, msgObject);
		case "INVALID_MESSAGE":
			log.info("Invalid message return:" + (String) msgObject.get("info"));
			return true;
		case "AUTHENTICATION_FAIL":
			log.info("Authentication fail return:" + (String) msgObject.get("info"));
			return true;
		case "LOGIN":
			log.info("Login Method initiated for username :" + (String) msgObject.get("username"));
			return loginUser(con, msg);
		case "LOGOUT":
			log.info("Log out");
			return true;
		case "ACTIVITY_MESSAGE":
			return activityMessage(con, msg);
		case "ACTIVITY_BROADCAST":
			return broadcastActivities(con, msg);
		case "SERVER_ANNOUNCE":
			return receiveAnnouncement(con, msgObject);
		case "REGISTER":
			return registerUser(con, msgObject);
		case "LOCK_REQUEST":
			return receiveLockRequest(con, msgObject);
		case "LOCK_DENIED":
			return receiveLockReply(con, msgObject, true);
		case "LOCK_ALLOWED":
			return receiveLockReply(con, msgObject, false);
		case "NEW_REGISTER_ANNOUNCEMENT":
			return updateKeyValue(con, msgObject);
		default:
			responseInvalidMsg("command is not exist", con);
			return true;
		}
	}

	/*
	 * sending message functions
	 */

	private boolean updateKeyValue(Connection con, JSONObject msgObject) {
		// System.out.println("Shajids updateKeyValue entered..."+msgObject.toJSONString());
		String username = msgObject.get("username").toString();
		String password = msgObject.get("password").toString();

		keySecretPairs.put(username, password);
		System.out.println(username);
		return false;
	}

	/*
	 * Added by shajidm@student.unimelb.edu.au to define the LogIn Method
	 */
	private synchronized boolean loginUser(Connection con, String msg) {
		try {
			String cmd = null;
			String info = null;

			JSONObject loginObject = (JSONObject) parser.parse(msg);
			if (!loginObject.containsKey("username")) {
				responseInvalidMsg("The instruction misses a username", con);
				return true;
			} else {

				String username = (String) loginObject.get("username");
				String secret = "";
				if (!username.equalsIgnoreCase("anonymous")) {
					secret = (String) loginObject.get("secret");
				}

				// Search for the username
				// If username is found
				if (keySecretPairs.containsKey(username)) {
					// compare the secretkeys
					if (keySecretPairs.get(username).equals(secret)) {
						cmd = "LOGIN_SUCCESS";
						info = "logged in as user " + username;
						con.setUsername(username);
						con.setSecret(secret);
						Settings.setUsername(username);
						Settings.setUserSecret(secret);
						responseMsg(cmd, info, con);

						int currentLoad = loadNum();

						JSONObject target = null;
						Long tempload = (long) currentLoad;
						for (JSONObject jsonAvailabilityObj : announcementInfo) {
							Long newLoad = (Long) jsonAvailabilityObj.get("load");
							if (((newLoad+1) < currentLoad) && (newLoad < Settings.getServerMaxLoad() )) {
								if(tempload > newLoad) {
								tempload = newLoad;
								target = jsonAvailabilityObj;
								}
							}
						}

						// shajid
						if (target != null) {
							String newHostName = (String) target.get("hostname");
							Long newPort = (Long) target.get("port");
							cmd = "REDIRECT";
							keySecretPairs.remove(username);
							responseRedirectionMsg(cmd, newHostName, newPort, con);
							return true;
						} else if (target == null && currentLoad == (Settings.getServerMaxLoad()+1)) {
							System.out.println("currentLoad"+currentLoad);
							// shajid code for creating a new server starts

							String OS = System.getProperty("os.name").toLowerCase();
							Long portNumber = findOpenPortsOnCurrentHostInterfaces();
							if (OS.indexOf("win") >= 0) {
								System.out.println("This is Windows");
								String currentDir = System.getProperty("user.dir");
								Runtime rt = Runtime.getRuntime();
								rt.exec("cmd.exe /c cd \""+currentDir+"\" & start cmd.exe /k \"java -jar "+currentDir+"/Server.jar -rp "+String.valueOf(Settings.getLocalPort())+" -rh "+Settings.getLocalHostname()+" -lp "+	 String.valueOf(portNumber)+" \"");

							} else if (OS.indexOf("mac") >= 0) {
								String currentDir = System.getProperty("user.dir");
								try {
									final ProcessBuilder processBuilder = new ProcessBuilder("/usr/bin/osascript", "-e",
											"tell app \"Terminal\"", "-e",
											"set currentTab to do script "
													+ "(\"java -jar "+currentDir+"/Server.jar -rp "+String.valueOf(Settings.getLocalPort())+" -rh "+Settings.getLocalHostname()+" -lp "+	 String.valueOf(portNumber)+" \")",
											"-e", "end tell");
									final Process process = processBuilder.start();
									process.waitFor();

								} catch (Exception e) {
									return false;
								}
								
							} else if (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0) {
								System.out.println("This is Unix or Linux");
								String currentDir = System.getProperty("user.dir");
								Runtime rt = Runtime.getRuntime();
								rt.exec("/bin/bash -c \"java -jar "+currentDir+"/Server.jar -rp "+String.valueOf(Settings.getLocalPort())+" -rh "+Settings.getLocalHostname()+" -lp "+	 String.valueOf(portNumber)+" \"");

							} else {
								System.out.println("Your OS is not support!!");
							}

							TimeUnit.SECONDS.sleep(30);


							// shajid code for creating a new server ends

							String newHostName = Settings.getLocalHostname();
							Long newPort = portNumber;
							cmd = "REDIRECT";
							keySecretPairs.remove(username);
							responseRedirectionMsg(cmd, newHostName, newPort, con);
							return true;
						} else {
							return false;
						}

					} else {
						return loginFailed("secret:" + secret + " not right", con);
					}

				} else {
					// If username is not found, login failed
					return loginFailed("User not found ", con);
				}

			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private boolean loginFailed(String info, Connection con) {
		responseMsg("LOGIN_FAILED", info, con);
		connectionClosed(con);
		return true;
	}

	/*
	 * add by yicongLI 19-04-18 send authenticate
	 */
	@SuppressWarnings("unchecked")
	private synchronized void authenticateRequest(Connection outCon) {
		JSONObject msgObj = new JSONObject();
		msgObj.put("command", "AUTHENTICATE");
		msgObj.put("secret", Settings.getServerSecret());
		outCon.writeMsg(msgObj.toJSONString());
	}

	/*
	 * add bybroadcast server load state to the other servers
	 */
	@SuppressWarnings("unchecked")
	private synchronized void regularAnnouncement() {
		String hostname = Settings.getIp();

		JSONObject msgObj = new JSONObject();
		msgObj.put("command", "SERVER_ANNOUNCE");
		msgObj.put("id", uniqueID);
		msgObj.put("load", loadNum());
		msgObj.put("hostname", hostname);
		msgObj.put("port", Settings.getLocalPort());
		msgObj.put("keySecretPairs",keySecretPairs);
		broadcastMessage(null, msgObj.toJSONString(), true);
	}
	
	//shajid
	@SuppressWarnings("unchecked")
	private synchronized void KeyUpdateAnnouncement(String username, String password) {
		String hostname = Settings.getIp();

		JSONObject msgObj = new JSONObject();
		msgObj.put("command", "NEW_REGISTER_ANNOUNCEMENT");
		msgObj.put("id", uniqueID);
		msgObj.put("load", loadNum());
		msgObj.put("hostname", hostname);
		msgObj.put("port", Settings.getLocalPort());
		msgObj.put("username", username);
		msgObj.put("password", password);

		broadcastMessage(null, msgObj.toJSONString(), true);
		
	}
	

	private synchronized Integer loadNum() {
		Integer load = 0;

		for (Connection con : connections) {
			if (!con.getIsServer()) {
				load++;
			}
		}

		return load;
	}

	/*
	 */
	@SuppressWarnings("unchecked")
	private synchronized void lockRequest(String userName, String secret, Connection clientCon) {
		JSONObject msgObj = new JSONObject();
		msgObj.put("command", "LOCK_REQUEST");
		msgObj.put("username", userName);
		msgObj.put("secret", secret);

		Integer outNum = broadcastMessage(null, msgObj.toJSONString(), true);

		if (outNum == 0) {
		
			String filename = String.valueOf(Settings.getLocalPort()) + ".json";
			File f = new File(filename);

			boolean check = false;
			// file is already existed
			if (f.exists()) {
				check = checkLocalStorage(filename, userName);
				// Register failed, found the user in the system
				if (check) {
					registerFail(userName, clientCon);
				} else {
					registerSuccess(userName, secret, clientCon, filename);
				}
			} else {
				createNewFile();
				registerSuccess(userName, secret, clientCon, filename);
			}
		} else {
			lockItemArray.add(new LockItem(userName, clientCon, outNum));
		}

	}

	/*
	 * 
	 * @param con: the connection from which receive the message, if null, then
	 * broadcast to all the other connections
	 * 
	 * @param msg: broadcast message
	 * 
	 * @param onlySever: if ture, then just broadcast to the other servers.
	 */
	private synchronized Integer broadcastMessage(Connection con, String msg, boolean onlySever) {
		Integer broadcastTime = 0;
		
		for (Connection broadcastCon : connections) {
			activeUsers.remove(broadcastCon.username());
			// when server to server only, if the connection is client,
			// then ignore it and check next one
			if (onlySever && !broadcastCon.getIsServer()) {
				continue;
			}

			// if con is equal to null, then broad cast to all connection
			if (con == null) {
				broadcastCon.writeMsg(msg);
				broadcastTime++;
				continue;
			}

			String conAddress = Settings.socketAddress(con.getSocket());
			String broadcastAddress = Settings.socketAddress(broadcastCon.getSocket());
			if (!conAddress.equals(broadcastAddress)) {
				broadcastCon.writeMsg(msg);
				broadcastTime++;
			}
		}
		
		for(String activeUser : activeUsers) {
			
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date d1 = new Date();
			dateFormat.format(d1);
			
			MessageQueue queue = new MessageQueue();
			queue.setActivityMessage(msg);
			queue.setUsername(activeUser);
			queue.setDateTime(d1);
			
			outgoingActivityObjectQueue.add(queue);
		
		}
		
		for (Connection broadcastCon : connections) {
			for(MessageQueue queue : outgoingActivityObjectQueue) {
				if(broadcastCon.username().equals(queue.getUsername())) {
					broadcastCon.writeMsg(msg);
					outgoingActivityObjectQueue.remove(queue);
					broadcastTime++;
				}
			}
		}
		
		return broadcastTime;
	}

	/*
	 * received message response functions
	 */

	/*
	 * add by 19-04-18 return invalid message info and close connection
	 */
	private synchronized void responseInvalidMsg(String info, Connection con) {
		responseMsg("INVALID_MESSAGE", info, con);
		connectionClosed(con);
	}

	// thaol4
	// return the response with format {"command":"","info":""}
	@SuppressWarnings("unchecked")
	private void responseMsg(String cmd, String info, Connection con) {
		JSONObject msgObj = new JSONObject();
		msgObj.put("command", cmd);
		msgObj.put("info", info);
		con.writeMsg(msgObj.toJSONString());

		log.info(msgObj.toJSONString());
	}
	/*
	 * Added by shajidm@student.unimelb.edu.au to define the responseRedirectionMsg
	 * Method
	 */

	@SuppressWarnings("unchecked")
	private void responseRedirectionMsg(String cmd, String hostname, Long port, Connection con) {
		JSONObject msgObj = new JSONObject();
		msgObj.put("command", cmd);
		msgObj.put("hostname", hostname);
		msgObj.put("port", port);
		con.writeMsg(msgObj.toJSONString());
	}

	/*
	 * add by yicongLI 18-04-19 check authentication requested from another server
	 */
	private synchronized boolean authentication(Connection con, JSONObject authObj) {
		if (!authObj.containsKey("secret")) {
			responseInvalidMsg("authentication invalid: no secret", con);
			return true;
		}

		String secret = (String) authObj.get("secret");
		if (!secret.equals(Settings.getServerSecret())) {
			String info = "the supplied secret is incorrect: " + secret;
			responseMsg("AUTHENTICATION_FAIL", info, con);
			connectionClosed(con);
			return true;
		}

		// No reply if the authentication succeeded
		con.setIsServer(true);
		con.setSecret(Settings.getServerSecret());
		return false;
	}

	// check if local storage contains username
	private boolean checkLocalStorage(String filename, String username) {
		try {
			Reader in = new FileReader(filename);
			JSONObject userlist = (JSONObject) parser.parse(in);
			// username is found
			if (userlist.containsKey(username)) {
				return true;
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		// username is not found
		return false;

	}

	// register fail, server replies, close connection
	private void registerFail(String username, Connection con) {
		String cmd = "REGISTER_FAILED";
		String info = username + " is already registered with the system";
		responseMsg(cmd, info, con);
		connectionClosed(con);
	}

	// register success, append new username and secret pair to file, server replies
	@SuppressWarnings("unchecked")
	private void registerSuccess(String username, String secret, Connection con, String filename) {
		
		
		File folder = new File(System.getProperty("user.dir"));
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			if (listOfFiles[i].isFile() && listOfFiles[i].getName().endsWith(".json")) {
				
				filename  = listOfFiles[i].getName();
				
				String cmd = "REGISTER_SUCCESS";
				String info = "register success for " + username;
				responseMsg(cmd, info, con);
				try {
					Reader in = new FileReader(filename);
					JSONObject userlist = (JSONObject) parser.parse(in);
					userlist.put(username, secret);
					FileWriter file = new FileWriter(filename);
					file.write(userlist.toJSONString());
					file.flush();
					file.close();

					log.info(userlist.toJSONString());
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ParseException e) {
					e.printStackTrace();
				}
			} 
		}
		
		
	

		// After register successfully, login
		String loginMsg = "{\"command\":\"LOGIN\",\"username\":\"" + username + "\",\"secret\" :\"" + secret + "\"}";
		loginUser(con, loginMsg);
	}

	private synchronized boolean registerUser(Connection con, JSONObject regObj) {
		// The msg is invalid
		if (!regObj.containsKey("username")) {
			responseInvalidMsg("the message must contain non-null key username", con);
			return true;
		}

		if (!regObj.containsKey("secret")) {
			responseInvalidMsg("the message must contain non-null key secret", con);
			return true;
		}

		String username = (String) regObj.get("username");
		String secret = (String) regObj.get("secret");
		if(keySecretPairs.containsKey(username)) {
			registerFail(username, con);
			return true;
		}
		keySecretPairs.put(username, secret);
		// After register successfully, login
		String loginMsg = "{\"command\":\"LOGIN\",\"username\":\"" + username + "\",\"secret\" :\"" + secret + "\"}";
		boolean loginFailed = loginUser(con, loginMsg);
		if(!loginFailed) {
			KeyUpdateAnnouncement(username, secret);
		}
		return false;
		
	}
	
//	private synchronized boolean syncKeyFiles() {
//	
//	}

	/*
	 *  handling the operation when receive lock_request
	 * modified by thaol4
	 */

	@SuppressWarnings("unchecked")
	private synchronized boolean receiveLockRequest(Connection con, JSONObject msgObj) {
		if (!con.getIsServer()) {
			responseInvalidMsg("Message received from an unauthenticated server", con);
			return true;
		} else if (!msgObj.containsKey("username")) {
			responseInvalidMsg("Message does not contain the id field", con);
			return true;
		} else if (!msgObj.containsKey("secret")) {
			responseInvalidMsg("Message does not contain the hostname field", con);
			return true;
		}

		String username = (String) msgObj.get("username");
		String secret = (String) msgObj.get("secret");
		boolean foundLocalName = false;

		// TODO check local userInfo
		String filename = String.valueOf(Settings.getLocalPort()) + ".json";
		File f = new File(filename);

		if (f.exists()) {
			foundLocalName = checkLocalStorage(filename, username);
		} else {
			foundLocalName = false;
		}

		if (foundLocalName) {
			// if found name in local storage, then reply the deny message
			msgObj.put("command", "LOCK_DENIED");
			con.writeMsg(msgObj.toJSONString());

			log.info(msgObj.toJSONString());
		} else {
			try {
				if (f.exists()) {
					Reader in = new FileReader(filename);
					JSONObject userlist = (JSONObject) parser.parse(in);
					userlist.put(username, secret);
					FileWriter file = new FileWriter(filename);
					file.write(userlist.toJSONString());
					file.flush();
					file.close();
					// file is not existed, create new one
				} else {
					createNewFile();
				}

			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// if this server is the end of the tree, then reply directly
			Integer outNum = broadcastMessage(con, msgObj.toJSONString(), true);
			if (outNum == 0) {
				msgObj.put("command", "LOCK_ALLOWED");
				con.writeMsg(msgObj.toJSONString());
				log.info(msgObj.toJSONString());
			} else {
				lockItemArray.add(new LockItem((String) msgObj.get("username"), con, outNum));
			}
		}
		return false;
	}

	/*
	 * add by yicongLI 23-04-18 handling the operation when receive lock_deny or
	 * lock_allow from another server
	 */
	// modified by thaol4
	private synchronized boolean receiveLockReply(Connection con, JSONObject msgObj, boolean isDeny) {
		if (!con.getIsServer()) {
			responseInvalidMsg("Message received from an unauthenticated server", con);
			return true;
		} else if (!msgObj.containsKey("username")) {
			responseInvalidMsg("Message does not contain the id field", con);
			return true;
		} else if (!msgObj.containsKey("secret")) {
			responseInvalidMsg("Message does not contain the hostname field", con);
			return true;
		}

		String userName = (String) msgObj.get("username");
		String secret = (String) msgObj.get("secret");

		Predicate<? super LockItem> filter = s -> userName.equals(s.getUserName());
		List<LockItem> curItem = lockItemArray.stream().filter(filter).collect(Collectors.toList());
		// if receive deny msg, then check if local has the usename with same secret, if
		// have then delete it
		if (isDeny) {
			if (!curItem.isEmpty()) {
				LockItem item = (LockItem) curItem.get(0);
				// if this server is the origin lock_request sending server
				// then should reply the client fail msg
				if (!item.getOriginCon().getIsServer()) {
					// TODO: reply client the register fail msg
					registerFail(userName, item.getOriginCon());
				}

				// remove record item from array
				lockItemArray.remove(item);

				// TODO: delete the local same username
				String filename = String.valueOf(Settings.getLocalPort()) + ".json";
				try {
					Reader in = new FileReader(filename);
					JSONObject userlist = (JSONObject) parser.parse(in);
					if (userlist.containsKey(userName)) {
						userlist.remove(userName);
						FileWriter file = new FileWriter(filename);
						file.write(userlist.toJSONString());
						file.flush();
						file.close();

					}
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ParseException e) {
					e.printStackTrace();
				}
			}
			// broadcast deny msg to other server
			broadcastMessage(con, msgObj.toJSONString(), true);
		} else {
			// if receive lock allow message, then check if every request has received
			// if all received, reply register success.
			if (!curItem.isEmpty()) {
				LockItem item = (LockItem) curItem.get(0);
				if (item.replyOrginCon()) {
					if (!item.getOriginCon().getIsServer()) {
						// TODO: reply the register success message
						String filename = String.valueOf(Settings.getLocalPort()) + ".json";
						registerSuccess(userName, secret, item.getOriginCon(), filename);

						// item.getOriginCon().writeMsg();
					} else {
						// reply the origin server the lock allow msg
						item.getOriginCon().writeMsg(msgObj.toJSONString());
					}

					lockItemArray.remove(item);
				}
			}
		}
		return false;
	}

	/*
	 * add by yicongLI 19-04-18 broadcast activities
	 */
	// modified and finished -- pateli
	@SuppressWarnings("unchecked")
	private synchronized boolean activityMessage(Connection con, String message) {

		
		
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date d1 = new Date();
		dateFormat.format(d1);
		
		MessageQueue queue = new MessageQueue();
		queue.setActivityMessage(message);
		queue.setUsername(con.username());
		queue.setDateTime(d1);
		
		incomingActivityObjectQueue.add(queue);
		
		
		for (Connection activeConnections : connections) {
			// If the connection is server, then ignore it and check next one
			if (!activeConnections.getIsServer()) {
				activeUsers.add(activeConnections.username());
			}
		}
		
		JSONObject msgObject = null;
		JSONObject activity_message = null;
		try {
			msgObject = (JSONObject) parser.parse(message);
			if (!msgObject.containsKey("activity")) {
				responseInvalidMsg("Message does not contain an activity object", con);
				return true;
			}
			if (!msgObject.containsKey("username")) {
				responseInvalidMsg("Message does not contain receiver's username", con);
				return true;
			}
			if (!msgObject.containsKey("secret")) {
				responseInvalidMsg("Message does not contain receiver's secret", con);
				return true;
			}

			// parse activity
			activity_message = (JSONObject) msgObject.get("activity");
			if (activity_message == null) {
				activity_message = new JSONObject();
			}
		} catch (Exception e) {
			e.printStackTrace();
			responseInvalidMsg("Message parse error", con);
			return true;
		}

		// auth
		String userName = (String) msgObject.get("username");
		String secret = (String) con.secrete();

		if (shoudAuthenticateUser(userName, secret, con)) {
			activity_message.put("authenticated_user", userName);

			JSONObject msgObjFinal = new JSONObject();
			msgObjFinal.put("command", "ACTIVITY_BROADCAST");
			msgObjFinal.put("activity", activity_message);

			broadcastMessage(con, msgObjFinal.toJSONString(), false);

			return false;
		} else {
			responseInvalidMsg("User not authenticated.", con);
			return true;
		}
	}

	/*
	 * add to check if can operate authentication
	 */
	private boolean shoudAuthenticateUser(String username, String secret, Connection con) {
		Boolean shouldAuthenticate = false;
		for (Connection connection : connections) {
			if (connection.username().equals(username) && connection.secrete().equals(secret)
					&& connection.equals(con)) {
				shouldAuthenticate = true;
			}
		}

		return shouldAuthenticate;
	}

	// added, modified and finished -- pateli
	private synchronized boolean broadcastActivities(Connection con, String message) {

		// check invalids
		JSONObject msgObject = null;
		try {
			msgObject = (JSONObject) parser.parse(message);
			if (!msgObject.containsKey("activity") || msgObject.get("activity") == null) {
				responseInvalidMsg("Message does not contain an activity object", con);
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
			responseInvalidMsg("Message parse error", con);
			return true;
		}

		// broadcast here
		broadcastMessage(con, msgObject.toJSONString(), false);
		return false;
	}

	/*
	 * add by  20-04-18 check authentication and store info after receiving
	 * announcement
	 */
	private synchronized boolean receiveAnnouncement(Connection con, JSONObject msgObj) {
		// check authentication of con
		if (!con.getIsServer()) {
			responseInvalidMsg("Message received from an unauthenticated server", con);
			return true;
		} else if (!msgObj.containsKey("id")) {
			responseInvalidMsg("Message does not contain the id field", con);
			return true;
		} else if (!msgObj.containsKey("hostname")) {
			responseInvalidMsg("Message does not contain the hostname field", con);
			return true;
		} else if (!msgObj.containsKey("port")) {
			responseInvalidMsg("Message does not contain the port field", con);
			return true;
		}
		
		if(msgObj.containsKey("keySecretPairs")) {
			JSONObject tempKeySecretPairs = (JSONObject) msgObj.get("keySecretPairs");
			keySecretPairs.putAll(tempKeySecretPairs);	
		}

		// update local info
		Integer sameInfoIndex = -1;
		String msgID = (String) msgObj.get("id");
		for (int j = 0; j < announcementInfo.size(); j++) {
			String infoID = (String) announcementInfo.get(j).get("id");
			if (msgID.equals(infoID)) {
				sameInfoIndex = j;
				break;
			}
		}

		// if find the info exist in Arraylist, then replace the info
		// else add to local storage.
		if (sameInfoIndex != -1) {
			announcementInfo.set(sameInfoIndex, msgObj);
		} else {
			announcementInfo.add(msgObj);
		}

		// broadcast message to other servers
		broadcastMessage(con, msgObj.toJSONString(), true);
		return false;
	}


	@SuppressWarnings("unchecked")
	private void createNewFile() {
		
		System.out.println("path is: "+System.getProperty("user.dir"));
		String originalFilename = "";
		File folder = new File(System.getProperty("user.dir"));
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			if (listOfFiles[i].isFile() && listOfFiles[i].getName().endsWith(".json")) {
				originalFilename = listOfFiles[i].getName();
				break;
			} 
		}
		
		if(!originalFilename.equals("")) {
			File source = new File(originalFilename);
			File dest = new File(Settings.getLocalPort()+".json");
			try {
				Files.copy(source.toPath(),dest.toPath() );
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else{
		String filename = String.valueOf(Settings.getLocalPort()) + ".json";
		try {
			FileWriter filewriter = new FileWriter(filename);
			JSONObject obj = new JSONObject();
			obj.put("anonymous", "");
			filewriter.write(obj.toJSONString());
			filewriter.flush();
			filewriter.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	}

	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con) {
		if (!term)
			connections.remove(con);
	}

	/*
	 * A new incoming connection has been established, and a reference is returned
	 * to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException {
		log.debug("incomming connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;

	}

	/*
	 * A new outgoing connection has been established, and a reference is returned
	 * to it
	 */
	public synchronized Connection outgoingConnection(Socket s) throws IOException {
		log.debug("outgoing connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		/*
		 * add by yicongLI 19-04-18 test msg JSONObject student = new JSONObject();
		 * student.put("ID", 1); student.put("name", "Mike"); student.put("isEnrolled",
		 * true); c.writeMsg(student.toJSONString());
		 */
		connections.add(c);
		return c;

	}

	@Override
	public void run() {
		log.info("using activity interval of " + Settings.getActivityInterval() + " milliseconds");
		while (!term) {
			// do something with 5 second intervals in between
			try {
				regularAnnouncement(); //  start regular announcement
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
		}
		log.info("closing " + connections.size() + " connections");
		// clean up
		for (Connection connection : connections) {
			connection.closeCon();
		}
		listener.setTerm(true);
	}

	public final void setTerm(boolean t) {
		term = t;
	}

	public final ArrayList<Connection> getConnections() {
		return connections;
	}
}
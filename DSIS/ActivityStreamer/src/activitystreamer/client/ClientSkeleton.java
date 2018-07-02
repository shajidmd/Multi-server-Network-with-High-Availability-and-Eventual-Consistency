package activitystreamer.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ClientSkeleton extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSkeleton clientSolution;
	private TextFrame textFrame;

	private Socket socket;
	private JSONParser parser;
	private BufferedReader reader;
	private BufferedWriter writer;
	private String nextSecret = null;
	private String username = null;
	private boolean term = false; // true if the connection is closed

	public static ClientSkeleton getInstance() {
		if (clientSolution == null) {
			clientSolution = new ClientSkeleton();
		}
		return clientSolution;
	}

	public ClientSkeleton() {
		parser = new JSONParser();
		textFrame = new TextFrame();
		username = Settings.getUsername();
		initialConnectionOperation();
		start();
	}
	
	/*
	 * all initial connect operations
	 * */
	public void initialConnectionOperation () {
		initializeConnection();
		String usersecret = Settings.getUserSecret();
		if (username != "anonymous") {
			if (usersecret == "") {
				sendRegisterObject(username);
			} else {
				sendLoginObject(username, usersecret);
			}
		} else {
			sendLoginObject(username, "");
		}
	}

	public void initializeConnection() {
		int port = Settings.getRemotePort();
		String hostname = Settings.getRemoteHostname();
		try {
			socket = new Socket(hostname, port);
			reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
			writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// shajidm
	public void sendLoginObject(String username, String secret) {
		try {
			String LoginCMDString = "{\"command\":\"LOGIN\",\"username\":\"" + username + "\",\"secret\" :\"" + secret
					+ "\"}";
			writer.write(LoginCMDString + "\n");
			writer.flush();

			log.info(LoginCMDString);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void sendRegisterObject(String username) {
		try {
			nextSecret = Settings.nextSecret();
			String registerCMD = "{\"command\":\"REGISTER\",\"username\":\"" + username + "\",\"secret\" :\""
					+ nextSecret + "\"}";
			writer.write(registerCMD + "\n");
			writer.flush();

			log.info(registerCMD);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// modified and finished 
	@SuppressWarnings("unchecked")
	public void sendActivityObject(String msg) {
		String origin = textFrame.getOutputText();
		textFrame.setOutputText(origin + "self : " + msg + "\n");

		JSONObject msgObjFinal = new JSONObject();
		msgObjFinal.put("command", "ACTIVITY_MESSAGE");
		msgObjFinal.put("username", Settings.getUsername());
		msgObjFinal.put("secret", Settings.getUserSecret());
		JSONObject json = new JSONObject();
		json.put("note", msg);

		msgObjFinal.put("activity", json);
		try {
			writer.write(msgObjFinal.toJSONString() + "\n");
			writer.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

		log.info(msgObjFinal.toJSONString());
	}
	
	@SuppressWarnings("unchecked")
	public void logout() {
		JSONObject outobj = new JSONObject();
		outobj.put("command", "LOGOUT");
		try {
			writer.write(outobj.toString() + "\n");
			writer.flush();
		} catch (IOException e) {
			// e.printStackTrace();
		}
	}

	public void disconnect(boolean isRedirect) {
		try {
			if (socket != null) {
				logout();
				writer.close();
				reader.close();
				socket.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			log.debug("Connection is closed");
			if (!isRedirect) {
				System.exit(0);	
			}
		}
	}

	@SuppressWarnings("unchecked")
	public boolean receiveMsg(JSONObject reobj) {
		String command = (String) reobj.get("command");
		switch (command) {
		case "INVALID_MESSAGE":
			System.out.println(reobj.get("info").toString());
			return true;
		case "AUTHENTICATION_FAIL":
			System.out.println(reobj.get("info").toString());
			return true;
		case "LOGIN_SUCCESS":
			System.out.println(reobj.get("info").toString());
			return false;
		case "REDIRECT": // shajidm
			String newHostName = (String) reobj.get("hostname");
			Long newPort = (Long) reobj.get("port");
			Settings.setRemoteHostname(newHostName);
			Settings.setRemotePort(newPort.intValue());
			// TODO: Close connection first, then create a new connection
			disconnect(true);
			initialConnectionOperation();
			return false;
		case "LOGIN_FAILED":
			System.out.println(reobj.get("info").toString());
			return true;
		case "ACTIVITY_BROADCAST":
			JSONObject actobj = (JSONObject) reobj.get("activity");
			String content = null;
			String userName = null;
			if (actobj.size() == 2) {
				for (Object key : actobj.keySet()) {
					String keyvalue = (String) key;
					if (!keyvalue.equals("authenticated_user")) {
						content = (String) actobj.get(keyvalue);
					} else {
						userName = (String) actobj.get(keyvalue);
					}
				}
			} else {
				content = actobj.toString();
			}

			String origin = textFrame.getOutputText();
			textFrame.setOutputText(origin + userName + " : " + content + "\n");
			return false;
		case "REGISTER_SUCCESS":
			System.out.println("User " + username + " has secret: " + nextSecret);
			Settings.setUserSecret(nextSecret);
			return false;
		case "REGISTER_FAILED":
			System.out.println(reobj.get("info").toString());
			return true;
		default:
			JSONObject msgObj = new JSONObject();
			msgObj.put("command", "INVALID_MESSAGE");
			msgObj.put("info", "Command is not recognised");
			try {
				writer.write(msgObj.toJSONString() + "\n");
				writer.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return true;
		}

	}

	public void run() {
		try {
			String result = null;
			while (!term && (result = reader.readLine()) != null) {
				JSONObject reobj = (JSONObject) parser.parse(result);
				term = receiveMsg(reobj);
			}
			log.debug("connection closed");
			disconnect(false);
		} catch (IOException e) {
			log.debug("connection closed with exception");
			disconnect(false);
		} catch (ParseException e) {
			log.debug("connection closed with exception");
			disconnect(false);
		}
	}

}

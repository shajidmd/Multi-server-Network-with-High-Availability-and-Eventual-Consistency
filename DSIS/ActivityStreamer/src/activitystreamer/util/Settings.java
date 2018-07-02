package activitystreamer.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Enumeration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Settings {
	private static final Logger log = LogManager.getLogger();
	private static SecureRandom random = new SecureRandom();
	private static int localPort = 3780;
	private static String localHostname = "localhost";
	// private static String remoteHostname = "43.240.97.243";
	private static String remoteHostname = null;//"localhost";
	private static int remotePort = 3781;
	private static int activityInterval = 5000; // milliseconds
	private static String userSecret = "";
	private static String serverSecret = " gen1p85md2qnq0d59qll3fbcoa";
	private static String username = "anonymous";

	private static int serverMaxLoad = 5;

	public static int getServerMaxLoad() {
		return serverMaxLoad;
	}

	public static void setServerMaxLoad(int serverMaxLoad) {
		Settings.serverMaxLoad = serverMaxLoad;
	}

	public static int getLocalPort() {
		return localPort;
	}

	public static void setLocalPort(int localPort) {
		if (localPort < 0 || localPort > 65535) {
			log.error("supplied port " + localPort + " is out of range, using " + getLocalPort());
		} else {
			Settings.localPort = localPort;
		}
	}

	public static int getRemotePort() {
		return remotePort;
	}

	public static void setRemotePort(int remotePort) {
		if (remotePort < 0 || remotePort > 65535) {
			log.error("supplied port " + remotePort + " is out of range, using " + getRemotePort());
		} else {
			Settings.remotePort = remotePort;
		}
	}

	public static String getRemoteHostname() {
		return remoteHostname;
	}

	public static void setRemoteHostname(String remoteHostname) {
		Settings.remoteHostname = remoteHostname;
	}

	public static int getActivityInterval() {
		return activityInterval;
	}

	public static void setActivityInterval(int activityInterval) {
		Settings.activityInterval = activityInterval;
	}

	public static String getUserSecret() {
		return userSecret;
	}

	public static void setUserSecret(String s) {
		userSecret = s;
	}

	public static String getServerSecret() {
		return serverSecret;
	}

	public static void setServerSecret(String s) {
		serverSecret = s;
	}

	public static String getUsername() {
		return username;
	}

	public static void setUsername(String username) {
		Settings.username = username;
	}

	public static String getLocalHostname() {
		return localHostname;
	}

	public static void setLocalHostname(String localHostname) {
		Settings.localHostname = localHostname;
	}

	/*
	 * some general helper functions
	 */

	public static String socketAddress(Socket socket) {
		return socket.getInetAddress() + ":" + socket.getPort();
	}

	public static String nextSecret() {
		return new BigInteger(130, random).toString(32);
	}

	/*
	 * add by 23-04-18 get real IP address
	 */
	public static String getIp() {
		String localip = null;// local IP
		String netip = null;// net IP
		try {
			Enumeration<NetworkInterface> netInterfaces = NetworkInterface.getNetworkInterfaces();
			InetAddress ip = null;
			boolean finded = false;// if find net IP
			while (netInterfaces.hasMoreElements() && !finded) {
				NetworkInterface ni = netInterfaces.nextElement();
				Enumeration<InetAddress> address = ni.getInetAddresses();
				while (address.hasMoreElements()) {
					ip = address.nextElement();
					if (!ip.isSiteLocalAddress() && !ip.isLoopbackAddress() && ip.getHostAddress().indexOf(":") == -1) {// net
																														// IP
						netip = ip.getHostAddress();
						finded = true;
						break;
					} else if (ip.isSiteLocalAddress() && !ip.isLoopbackAddress()
							&& ip.getHostAddress().indexOf(":") == -1) {// local IP
						localip = ip.getHostAddress();
					}
				}
			}
		} catch (SocketException e) {
			e.printStackTrace();
		}
		if (netip != null && !"".equals(netip)) {
			return netip;
		} else {
			return localip;
		}
	}
}

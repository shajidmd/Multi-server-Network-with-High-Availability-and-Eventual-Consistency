package activitystreamer.server;

import java.util.Date;

import org.json.simple.JSONObject;

public class MessageQueue implements Comparable<MessageQueue> {

	private String username;
	private String activityMessage;
	private Date dateTime;

	public Date getDateTime() {
		return dateTime;
	}

	public void setDateTime(Date datetime) {
		this.dateTime = datetime;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getActivityMessage() {
		return activityMessage;
	}

	public void setActivityMessage(String activityMessage) {
		this.activityMessage = activityMessage;
	}

	@Override
	public int compareTo(MessageQueue o) {
		if (getDateTime() == null || o.getDateTime() == null) {
		      return 0;
		}
		   return getDateTime().compareTo(o.getDateTime());	}
}

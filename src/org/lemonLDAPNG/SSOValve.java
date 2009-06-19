package org.lemonLDAPNG;

import java.io.IOException;
import java.lang.Boolean;
import java.lang.String;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.tomcat.util.compat.JdkCompat;
/**
 * SSO Valve for lemonLDAPNG
 * 
 * 
 * @author PEJAC Pascal
 *
 */
public class SSOValve extends ValveBase {
	private static Log log;

	static {
		log = LogFactory.getLog(org.lemonLDAPNG.SSOValve.class);
	}

	private static final JdkCompat jdkCompat = JdkCompat.getJdkCompat();

	private static final String info = "org.lemonLDAPNG.SSOValve/1.0";

	private String userKey = null;

	private String roleKey = null;

	private String roleSeparator = null;

	boolean flagAllows = false;
	
	// By default allow all hosts
	private Pattern allows[] = {Pattern.compile("^.*$")};

	private boolean passThrough = false;

	public String getInfo() {
		return info;
	}

	public void invoke(Request request, Response response) throws IOException,
			ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request
				.getRequest();
		// get the remote IP
		String remoteAdress = request.getRequest().getRemoteAddr();
		// check if remote adress is allowed in our list
		for (int j = 0; j < allows.length; j++) {
			if (log.isDebugEnabled())
				log.debug("Pattern "+allows[j].pattern()+" tested on  ip remote "+remoteAdress);
			if (allows[j].matcher(remoteAdress).matches()) {

				List<String> roles = new ArrayList<String>();
				// retrieve user and role
				String user = httpServletRequest.getHeader(userKey);
				String role = httpServletRequest.getHeader(roleKey);
				if (log.isDebugEnabled())
					log.debug("Processing WebSSO request for  "
							+ request.getMethod() + " "
							+ request.getRequestURI());
				if (user != null && role != null) {
					if (log.isDebugEnabled())
						log.debug("Found data User [ "
								+ user + "] with role [ "
								+ role+"]");
				}

				if (roleSeparator != null && role != null) {
					String res[] = role.split(roleSeparator);
					for (int i = 0; i < res.length; i++) {
						roles.add(res[i]);
					}
				} else {
					if (role != null)
						roles.add(role);
				}
				if (user != null) {
					request.setUserPrincipal(new GenericPrincipal(this
							.getContainer().getRealm(), user, "", roles));
				} else if (!passThrough) {
					if (log.isDebugEnabled())
						log.debug("PassThrough disable, send 403 error");
					response.sendError(403);
					return;
				}
				getNext().invoke(request, response);
				return;
			}
		}
		// error 403 => host not autorized
		if (flagAllows) response.sendError(403);
		return;
	}

	/**
	 * get all pattern from host list
	 * @param list
	 * @return
	 */
	protected Pattern[] precalculate(String list) {
		if (list == null)
			return new Pattern[0];
		list = list.trim();
		if (list.length() < 1)
			return new Pattern[0];
		list = list + ",";
		ArrayList<Pattern> reList = new ArrayList<Pattern>();
		do {
			if (list.length() <= 0)
				break;
			int comma = list.indexOf(',');
			if (comma < 0)
				break;
			String pattern = list.substring(0, comma).trim();
			try {
				reList.add(Pattern.compile(pattern));
			} catch (PatternSyntaxException e) {
				IllegalArgumentException iae = new IllegalArgumentException(sm
						.getString("requestFilterValve.syntax", pattern));
				jdkCompat.chainException(iae, e);
				throw iae;
			}
			list = list.substring(comma + 1);
		} while (true);
		Pattern reArray[] = new Pattern[reList.size()];
		return (Pattern[]) reList.toArray(reArray);
	}

	public String getUserKey() {
		return userKey;
	}

	public void setUserKey(String userKey) {
		this.userKey = userKey;
		if (log.isDebugEnabled() && userKey != null)
			log.debug("UserKey [" + this.userKey + "]");
	}

	public String getRoleKey() {
		return roleKey;
	}

	public void setRoleKey(String roleKey) {
		this.roleKey = roleKey;
		if (log.isDebugEnabled() && roleKey != null)
			log.debug("RoleKey [" + this.roleKey + "]");
	}

	public String getRoleSeparator() {
		return roleSeparator;
	}

	public void setRoleSeparator(String roleSeparator) {
		this.roleSeparator = roleSeparator;
		if (log.isDebugEnabled() && roleSeparator != null)
			log.debug("RoleSeparator [" + this.roleSeparator + "]");
	}

	public String getAllows() {
		return "";
	}

	public void setAllows(String allows) {
		// override default allows
		this.allows = precalculate(allows);
		flagAllows = true;
	}

	public String getPassThrough() {
		return String.valueOf(passThrough);
	}

	public void setPassThrough(String passThrough) {
		this.passThrough = Boolean.valueOf(passThrough);
		if (log.isDebugEnabled() && passThrough != null)
			log.debug("PassThrough [" + this.passThrough + "]");
	}

}

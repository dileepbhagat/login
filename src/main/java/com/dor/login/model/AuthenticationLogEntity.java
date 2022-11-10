package com.dor.login.model;

import java.time.LocalDateTime;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="authentication_log", schema="login")
public class AuthenticationLogEntity {
	
	@Id
	@Column(name="serial_no")
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Integer serialNo;
	
	@Column(name="login_id")
	private String loginId;
	
	@Column(name = "loggged_in_timestamp")
	private LocalDateTime loggedInTimestamp;
	
	@Column(name = "logged_out_timestamp")
	private LocalDateTime loggedOutTimestamp;
	
	@Column(name = "ip_address")
	private String ipAddress;
	
	@Column(name = "status")
	private Boolean status;
	
	@Column(name = "logged_in")
	private Boolean loggedIn;
	
	@Column(name = "authenticated")
	private Boolean authenticated;
	
	@Column(name = "authenticated_app")
	private Integer authenticatedApp;

	@Column(name = "authenticated_timestamp")
	private LocalDateTime authenticatedTimestamp;
	
	@Column(name = "authentication_msg")
	private String authenticationMsg;
	
	@Column(name = "authenticated_on")
	private String authenticatedOn;

	public Integer getSerialNo() {
		return serialNo;
	}

	public void setSerialNo(Integer serialNo) {
		this.serialNo = serialNo;
	}

	public String getLoginId() {
		return loginId;
	}

	public Boolean getLoggedIn() {
		return loggedIn;
	}

	public void setLoggedIn(Boolean loggedIn) {
		this.loggedIn = loggedIn;
	}

	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}

	public LocalDateTime getLoggedInTimestamp() {
		return loggedInTimestamp;
	}

	public void setLoggedInTimestamp(LocalDateTime loggedInTimestamp) {
		this.loggedInTimestamp = loggedInTimestamp;
	}

	public LocalDateTime getLoggedOutTimestamp() {
		return loggedOutTimestamp;
	}

	public void setLoggedOutTimestamp(LocalDateTime loggedOutTimestamp) {
		this.loggedOutTimestamp = loggedOutTimestamp;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public Boolean getStatus() {
		return status;
	}

	public void setStatus(Boolean status) {
		this.status = status;
	}

	public Boolean getAuthenticated() {
		return authenticated;
	}

	public void setAuthenticated(Boolean authenticated) {
		this.authenticated = authenticated;
	}

	public Integer getAuthenticatedApp() {
		return authenticatedApp;
	}

	public void setAuthenticatedApp(Integer authenticatedApp) {
		this.authenticatedApp = authenticatedApp;
	}

	public LocalDateTime getAuthenticatedTimestamp() {
		return authenticatedTimestamp;
	}

	public void setAuthenticatedTimestamp(LocalDateTime authenticatedTimestamp) {
		this.authenticatedTimestamp = authenticatedTimestamp;
	}

	public String getAuthenticationMsg() {
		return authenticationMsg;
	}

	public void setAuthenticationMsg(String authenticationMsg) {
		this.authenticationMsg = authenticationMsg;
	}

	public String getAuthenticatedOn() {
		return authenticatedOn;
	}

	public void setAuthenticatedOn(String authenticatedOn) {
		this.authenticatedOn = authenticatedOn;
	}
	
}


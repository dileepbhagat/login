package com.dor.login.model;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="application", schema="login")
public class ApplicationEntity {
	
	@Id
	@Column(name="app_id")
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Integer appId;
	
	@Column(name="app_name")
	private String appName;
	
	@Column(name = "app_short_code")
	private String appShortCode;
	
	@Column(name = "admin_mob")
	private String adminMob;
	
	@Column(name = "admin_email")
	private String adminEmail;
	
	@Column(name = "key")
	private String key;
	
	@Column(name = "otp")
	private String otp;
	
	@Column(name = "created_on")
	private Date createdOn;
	
	@Column(name = "updated_on")
	private Date updatedOn;
	
	@Column(name = "enabled")
	private Boolean enabled;

	@Column(name = "email_verified")
	private Boolean emailVerified;
	
	@Column(name = "mob_verified")
	private Boolean mobVerified;
	
	public Integer getAppId() {
		return appId;
	}

	public void setAppId(Integer appId) {
		this.appId = appId;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getAppShortCode() {
		return appShortCode;
	}

	public void setAppShortCode(String appShortCode) {
		this.appShortCode = appShortCode;
	}

	public String getAdminMob() {
		return adminMob;
	}

	public void setAdminMob(String adminMob) {
		this.adminMob = adminMob;
	}

	public String getAdminEmail() {
		return adminEmail;
	}

	public void setAdminEmail(String adminEmail) {
		this.adminEmail = adminEmail;
	}

	public Date getCreatedOn() {
		return createdOn;
	}

	public void setCreatedOn(Date createdOn) {
		this.createdOn = createdOn;
	}

	public Date getUpdatedOn() {
		return updatedOn;
	}

	public void setUpdatedOn(Date updatedOn) {
		this.updatedOn = updatedOn;
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public Boolean getEmailVerified() {
		return emailVerified;
	}

	public void setEmailVerified(Boolean emailVerified) {
		this.emailVerified = emailVerified;
	}

	public Boolean getMobVerified() {
		return mobVerified;
	}

	public void setMobVerified(Boolean mobVerified) {
		this.mobVerified = mobVerified;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

}

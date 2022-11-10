package com.dor.login.dto;

import java.util.Date;

public class AuthenticatedUser {
	
	
	public Integer serialNo;
	public String loginId;
	public String loginTime;
	public Long frequency;
	public Date accessedDate;
	public String mobNo;
	
	public String getLoginId() {
		return loginId;
	}
	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}
	public Long getFrequency() {
		return frequency;
	}
	public void setFrequency(Long frequency) {
		this.frequency = frequency;
	}
	public Date getAccessedDate() {
		return accessedDate;
	}
	public void setAccessedDate(Date accessedDate) {
		this.accessedDate = accessedDate;
	}
	public Integer getSerialNo() {
		return serialNo;
	}
	public void setSerialNo(Integer serialNo) {
		this.serialNo = serialNo;
	}
	public String getLoginTime() {
		return loginTime;
	}
	public void setLoginTime(String loginTime) {
		this.loginTime = loginTime;
	}
	public String getMobNo() {
		return mobNo;
	}
	public void setMobNo(String mobNo) {
		this.mobNo = mobNo;
	}

}

package com.dor.login.dto;

public class AbstractResponseDTO {
	
	public  String msg;
	public Boolean status;
	
	public String getMsg() {
		return msg;
	}
	public void setMsg(String msg) {
		this.msg = msg;
	}
	public Boolean getStatus() {
		return status;
	}
	public void setStatus(Boolean status) {
		this.status = status;
	}
	
}

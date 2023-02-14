package com.dor.login.dto;

public class AuthenticatedUserListRequestDTO {
	
	public Integer appId;
	public Integer noOfDays;
	public Boolean daywise;
	public Boolean monthwise;
	public Boolean yearwise;
	public Boolean topwise;
	public Integer topNo;
	public Boolean bottomwise;
	public Integer bottomNo;
	public String day;
	public String month;
	public String year;
	
	
	public String firstDate;
	public String lastDate;
	
	public Integer getAppId() {
		return appId;
	}

	public void setAppId(Integer appId) {
		this.appId = appId;
	}

	public Integer getNoOfDays() {
		return noOfDays;
	}

	public void setNoOfDays(Integer noOfDays) {
		this.noOfDays = noOfDays;
	}

	public Boolean getDaywise() {
		return daywise;
	}

	public void setDaywise(Boolean daywise) {
		this.daywise = daywise;
	}

	public Boolean getMonthwise() {
		return monthwise;
	}

	public void setMonthwise(Boolean monthwise) {
		this.monthwise = monthwise;
	}

	public Boolean getYearwise() {
		return yearwise;
	}

	public void setYearwise(Boolean yearwise) {
		this.yearwise = yearwise;
	}

	public String getDay() {
		return day;
	}

	public void setDay(String day) {
		this.day = day;
	}

	public String getMonth() {
		return month;
	}

	public void setMonth(String month) {
		this.month = month;
	}

	public String getYear() {
		return year;
	}

	public void setYear(String year) {
		this.year = year;
	}

	public Boolean getTopwise() {
		return topwise;
	}

	public void setTopwise(Boolean topwise) {
		this.topwise = topwise;
	}

	public Integer getTopNo() {
		return topNo;
	}

	public void setTopNo(Integer topNo) {
		this.topNo = topNo;
	}

	public Boolean getBottomwise() {
		return bottomwise;
	}

	public void setBottomwise(Boolean bottomwise) {
		this.bottomwise = bottomwise;
	}

	public Integer getBottomNo() {
		return bottomNo;
	}

	public void setBottomNo(Integer bottomNo) {
		this.bottomNo = bottomNo;
	}

	public String getFirstDate() {
		return firstDate;
	}

	public void setFirstDate(String firstDate) {
		this.firstDate = firstDate;
	}

	public String getLastDate() {
		return lastDate;
	}

	public void setLastDate(String lastDate) {
		this.lastDate = lastDate;
	}
	
}

package com.whiteoaksecurity.copier.models;

import com.whiteoaksecurity.copier.GlobalCopyProfile;

public class RequestRulesTableModel extends RulesTableModel {

	public RequestRulesTableModel() {
		this.ruleType = "Request";
		this.locations = new String[]{
			"Request",
			"Request Line",
			"Request URL Param",
			"Request URL Param Name",
			"Request URL Param Value",
			"Request Headers",
			"Request Header",
			"Request Header Name",
			"Request Header Value",
			"Request Body",
			"Request Body Param",
			"Request Body Param Name",
			"Request Body Param Value"
		};
	}
}

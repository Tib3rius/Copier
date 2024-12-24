package com.whiteoaksecurity.copier;

import burp.api.montoya.http.message.HttpMessage;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class CopyProfile extends GlobalCopyProfile {
	
	private String name;
	
	@JsonCreator
	public CopyProfile(@JsonProperty("name") String name) {
		this.name = name;
	}
	
	@Override
	public String toString() {
		return this.name;
	}
	
	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}
}

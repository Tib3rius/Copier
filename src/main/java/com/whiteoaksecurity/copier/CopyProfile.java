package com.whiteoaksecurity.copier;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CopyProfile extends GlobalCopyProfile {
	
	private String name;
	private boolean skipGlobalRules = false;
	
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

	@JsonProperty("skipGlobalRules")
	public boolean getSkipGlobalRules() {
		return this.skipGlobalRules;
	}

	public void setSkipGlobalRules(boolean skipGlobalProfile) {
		this.skipGlobalRules = skipGlobalProfile;
	}
}

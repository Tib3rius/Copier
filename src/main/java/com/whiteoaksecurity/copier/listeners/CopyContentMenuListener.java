package com.whiteoaksecurity.copier.listeners;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import com.whiteoaksecurity.copier.CopyProfile;
import com.whiteoaksecurity.copier.GlobalCopyProfile;
import com.whiteoaksecurity.copier.Rule;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class CopyContentMenuListener implements ActionListener {

	private GlobalCopyProfile globalProfile;
	private CopyProfile profile;
	private boolean copyRequest;
	private boolean copyResponse;
	private ContextMenuEvent contextEvent;
	
	public CopyContentMenuListener(GlobalCopyProfile globalProfile, CopyProfile profile, boolean copyRequest, boolean copyResponse, ContextMenuEvent contextEvent) {
		this.globalProfile = globalProfile;
		this.profile = profile;
		this.copyRequest = copyRequest;
		this.copyResponse = copyResponse;
		this.contextEvent = contextEvent;
	}
	
	@Override
	public void actionPerformed(ActionEvent actionEvent) {
		StringBuilder copyBuffer = new StringBuilder();
		
		int counter = 1;
		ArrayList<HttpRequestResponse> requestResponses = new ArrayList<>();
		
		if (!this.contextEvent.selectedRequestResponses().isEmpty()) {
			// To save processing time, we combine the Global Profile and Selected Profile into one.
			CopyProfile tempProfile = new CopyProfile(this.profile.getName());
			RequestRulesTableModel tempRequestRulesTableModel = (RequestRulesTableModel) tempProfile.getRequestRulesTableModel();
			ResponseRulesTableModel tempResponseRulesTableModel = (ResponseRulesTableModel) tempProfile.getResponseRulesTableModel();

			for (Rule replacement : this.globalProfile.getRequestRulesTableModel().getData()) {
				tempRequestRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.profile.getRequestRulesTableModel().getData()) {
				tempRequestRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.globalProfile.getResponseRulesTableModel().getData()) {
				tempResponseRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.profile.getResponseRulesTableModel().getData()) {
				tempResponseRulesTableModel.add(replacement);
			}

			requestResponses.addAll(tempProfile.replace(this.contextEvent.selectedRequestResponses(), this.copyRequest, this.copyResponse));
		} else if (!this.contextEvent.messageEditorRequestResponse().isEmpty()) {

			// To save processing time, we combine the Global Profile and Selected Profile into one.
			CopyProfile tempProfile = new CopyProfile(this.profile.getName());
			RequestRulesTableModel tempRequestRulesTableModel = (RequestRulesTableModel) tempProfile.getRequestRulesTableModel();
			ResponseRulesTableModel tempResponseRulesTableModel = (ResponseRulesTableModel) tempProfile.getResponseRulesTableModel();

			for (Rule replacement : this.globalProfile.getRequestRulesTableModel().getData()) {
				tempRequestRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.profile.getRequestRulesTableModel().getData()) {
				tempRequestRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.globalProfile.getResponseRulesTableModel().getData()) {
				tempResponseRulesTableModel.add(replacement);
			}

			for (Rule replacement : this.profile.getResponseRulesTableModel().getData()) {
				tempResponseRulesTableModel.add(replacement);
			}

			requestResponses.add(tempProfile.replace(this.contextEvent.messageEditorRequestResponse().get().requestResponse(), this.copyRequest, this.copyResponse));
		}
		
		for (HttpRequestResponse httpRequestResponse : requestResponses) {
			if (this.copyRequest) {
				copyBuffer.append(new String(httpRequestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8));
			}
			
			if (this.copyRequest && this.copyResponse) {
				if (httpRequestResponse.request().body().length() > 0) {
					copyBuffer.append("\n\n");
				}
			}
			
			if (this.copyResponse) {
				copyBuffer.append(new String(httpRequestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8));
			}
			
			if (counter != requestResponses.size()) {
				copyBuffer.append("\n\n\n");
			}
			
			counter += 1;
		}
		
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer.toString()), null);
	}

}

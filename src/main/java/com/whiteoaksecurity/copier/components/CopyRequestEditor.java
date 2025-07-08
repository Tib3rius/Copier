package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.whiteoaksecurity.copier.*;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import javax.swing.*;

public class CopyRequestEditor implements ExtensionProvidedHttpRequestEditor {

	private final MontoyaApi api;
	private final GlobalCopyProfile globalProfile;
	private final JComboBox<CopyProfile> profiles;
	private final RawEditor requestEditor;
	private HttpRequestResponse requestResponse;
	private boolean includeURLBoolean = false;

	private final JPanel panel;
	private final JComboBox<CopyProfile> profileCombo;
	private final JButton copyButton;
	private final JButton copyBothButton;

	public CopyRequestEditor(MontoyaApi api, GlobalCopyProfile globalProfile, JComboBox<CopyProfile> profiles, EditorCreationContext creationContext) {
		this.api = api;
		this.globalProfile = globalProfile;
		this.profiles = profiles;
		this.requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES);

		panel = new JPanel();

		JLabel profileLabel = new JLabel("Profile:");
		profileLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize() + 1));
		profileLabel.setForeground(Copier.FONT_COLOR);

		profileCombo = new JComboBox<>();
		profileCombo.setMinimumSize(new Dimension(150, profileCombo.getPreferredSize().height));
		profileCombo.setMaximumSize(profileCombo.getPreferredSize());

		for (int i = 0; i < this.profiles.getItemCount(); i++) {
			if (this.profiles.getItemAt(i).getRequestRulesTableModel().getRowCount() > 0) {
				profileCombo.addItem(this.profiles.getItemAt(i));
			}
		}

		if (profileCombo.getItemCount() > 0) {
			profileCombo.setSelectedIndex(0);
		} else {
			profileCombo.addItem(new CopyProfile("No Valid Profiles"));
			profileCombo.setEnabled(false);
		}

		JCheckBox includeURL = new JCheckBox("Include URL");
		includeURL.setSelected(includeURLBoolean);
		includeURL.addActionListener((ActionEvent e) -> {
			includeURLBoolean = includeURL.isSelected();
		});

		copyButton = new JButton("Copy Request");
		copyButton.addActionListener((ActionEvent e) -> {
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + (new String(this.requestEditor.getContents().getBytes(), StandardCharsets.UTF_8))), null);
		});

		copyBothButton = new JButton("Copy Request + Response");
		copyBothButton.addActionListener((ActionEvent e) -> {
			String response;

			if (profileCombo.getSelectedItem() != null) {
				CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

				// To save processing time, we combine the Global Profile and Selected Profile into one.
				CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
				ResponseRulesTableModel tempResponseRulesTableModel = (ResponseRulesTableModel) tempProfile.getResponseRulesTableModel();

				if (!selectedProfile.getSkipGlobalRules()) {
					for (Rule replacement : globalProfile.getResponseRulesTableModel().getData()) {
						tempResponseRulesTableModel.add(replacement);
					}
				}

				for (Rule replacement : selectedProfile.getResponseRulesTableModel().getData()) {
					tempResponseRulesTableModel.add(replacement);
				}

				response = new String(tempProfile.replace(this.requestResponse, false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);

			} else {
				response = new String(this.requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
			}

			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + (new String(this.requestEditor.getContents().getBytes(), StandardCharsets.UTF_8)) + (this.requestResponse.request().body().length() == 0 ? "" : "\n\n") + response), null);
		});

		// Disable Copy Both button by default in case no response.
		copyBothButton.setEnabled(false);

		profileCombo.addActionListener((ActionEvent e) -> {
			this.requestEditor.setContents(ByteArray.byteArray("Running Request Copy Rules..."));
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);

			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					String request;
					if (profileCombo.getSelectedItem() != null) {
						CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

						// To save processing time, we combine the Global Profile and Selected Profile into one.
						CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
						RequestRulesTableModel tempRequestRulesTableModel = (RequestRulesTableModel) tempProfile.getRequestRulesTableModel();

						if (!selectedProfile.getSkipGlobalRules()) {
							for (Rule replacement : globalProfile.getRequestRulesTableModel().getData()) {
								tempRequestRulesTableModel.add(replacement);
							}
						}

						for (Rule replacement : selectedProfile.getRequestRulesTableModel().getData()) {
							tempRequestRulesTableModel.add(replacement);
						}

						request = new String(tempProfile.replace(requestResponse, true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);

					} else {
						request = new String(requestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
					}
					requestEditor.setContents(ByteArray.byteArray(request));
					copyButton.setEnabled(true);

					// Only re-enable Copy Both button if response exists.
					if (requestResponse.hasResponse()) {
						copyBothButton.setEnabled(true);
					}
				}
			});
		});

		GroupLayout layout = new GroupLayout(panel);
		layout.setAutoCreateGaps(true);
		panel.setLayout(layout);

		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGap(5)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
						.addComponent(profileLabel)
						.addComponent(profileCombo)
						.addComponent(copyButton)
						.addComponent(copyBothButton)
						.addComponent(includeURL)
				)
				.addGap(5)
				.addComponent(this.requestEditor.uiComponent())
		);

		layout.setHorizontalGroup(layout.createParallelGroup()
				.addGroup(layout.createSequentialGroup()
						.addGap(5)
						.addComponent(profileLabel)
						.addGap(5)
						.addComponent(profileCombo)
						.addGap(5)
						.addComponent(copyButton)
						.addGap(5)
						.addComponent(copyBothButton)
						.addGap(5)
						.addComponent(includeURL)
				)
				.addComponent(this.requestEditor.uiComponent())
		);
	}

	@Override
	public HttpRequest getRequest() {
		return this.requestResponse.request();
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse) {
		this.requestResponse = requestResponse;
		this.requestEditor.setContents(requestResponse.request().toByteArray());
	}

	@Override
	public boolean isEnabledFor(HttpRequestResponse requestReponse) {
		return true;
	}

	@Override
	public String caption() {
		return "Copy Request";
	}

	@Override
	public Component uiComponent() {
		// Run Request Copy Rules on UI Load.
		if (this.requestResponse != null && profileCombo.getItemCount() > 0) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					String request = (new String(requestEditor.getContents().getBytes(), StandardCharsets.UTF_8));;
					if (profileCombo.getSelectedItem() != null) {
						CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

						requestEditor.setContents(ByteArray.byteArray("Running Request Copy Rules..."));
						copyButton.setEnabled(false);
						copyBothButton.setEnabled(false);

						// To save processing time, we combine the Global Profile and Selected Profile into one.
						CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
						RequestRulesTableModel tempRequestRulesTableModel = (RequestRulesTableModel) tempProfile.getRequestRulesTableModel();

						if (!selectedProfile.getSkipGlobalRules()) {
							for (Rule replacement : globalProfile.getRequestRulesTableModel().getData()) {
								tempRequestRulesTableModel.add(replacement);
							}
						}

						for (Rule replacement : selectedProfile.getRequestRulesTableModel().getData()) {
							tempRequestRulesTableModel.add(replacement);
						}

						request = new String(tempProfile.replace(requestResponse, true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);
					}

					requestEditor.setContents(ByteArray.byteArray(request));
					copyButton.setEnabled(true);

					// Only re-enable Copy Both button if response exists.
					if (requestResponse.hasResponse()) {
						copyBothButton.setEnabled(true);
					}
				}
			});
		}

		return panel;
	}

	@Override
	public Selection selectedData() {
		return this.requestEditor.selection().isEmpty() ? Selection.selection(this.requestEditor.selection().get().contents()) : null;
	}

	@Override
	public boolean isModified() {
		return false;
	}

}
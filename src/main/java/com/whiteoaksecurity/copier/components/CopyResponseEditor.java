package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.whiteoaksecurity.copier.*;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;

import javax.swing.*;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;

public class CopyResponseEditor implements ExtensionProvidedHttpResponseEditor {
	
	private final MontoyaApi api;
	private final GlobalCopyProfile globalProfile;
	private final JComboBox<CopyProfile> profiles;
	private final JTextArea responseEditor;
	private HttpRequestResponse requestResponse;
	private boolean includeURLBoolean = false;
	private CopyProfile lastRunProfile = null;

	public CopyResponseEditor(MontoyaApi api, GlobalCopyProfile globalProfile, JComboBox<CopyProfile> profiles, EditorCreationContext creationContext) {
		this.api = api;
		this.globalProfile = globalProfile;
		this.profiles = profiles;
		this.responseEditor = new JTextArea();
		this.responseEditor.setLineWrap(true);
		this.responseEditor.setWrapStyleWord(false);
		this.responseEditor.setFont(api.userInterface().currentEditorFont());
				
		if (creationContext.editorMode() == EditorMode.READ_ONLY) {
			this.responseEditor.setEditable(false);
		}
	}

	@Override
	public HttpResponse getResponse() {
		return this.requestResponse.response();
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse) {
		this.requestResponse = requestResponse;
		this.responseEditor.setText(requestResponse.response().toByteArray().toString());
	}

	@Override
	public boolean isEnabledFor(HttpRequestResponse requestReponse) {
		return true;
	}

	@Override
	public String caption() {
		return "Copy Response";
	}

	@Override
	public Component uiComponent() {
		JPanel panel = new JPanel();

		JLabel profileLabel = new JLabel("Profile:");
		profileLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize() + 1));
		profileLabel.setForeground(Copier.FONT_COLOR);

		JComboBox<CopyProfile> profileCombo = new JComboBox<>();
		profileCombo.setMinimumSize(new Dimension(150, profileCombo.getPreferredSize().height));
		profileCombo.setMaximumSize(profileCombo.getPreferredSize());

		for (int i = 0; i < this.profiles.getItemCount(); i++) {
			if (this.profiles.getItemAt(i).getResponseRulesTableModel().getRowCount() > 0) {
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

		JButton copyButton = new JButton("Copy Response");
		copyButton.addActionListener((ActionEvent e) -> {
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + this.responseEditor.getText()), null);
		});

		JButton copyBothButton = new JButton("Copy Request + Response");
		copyBothButton.addActionListener((ActionEvent e) -> {
			String request;

			if (profileCombo.getSelectedItem() != null) {
				CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

				// To save processing time, we combine the Global Profile and Selected Profile into one.
				CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
				RequestRulesTableModel tempRequestRulesTableModel = (RequestRulesTableModel) tempProfile.getRequestRulesTableModel();

				for (Rule replacement : globalProfile.getRequestRulesTableModel().getData()) {
					tempRequestRulesTableModel.add(replacement);
				}

				for (Rule replacement : selectedProfile.getRequestRulesTableModel().getData()) {
					tempRequestRulesTableModel.add(replacement);
				}

				request = new String(tempProfile.replace(this.requestResponse, true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);

			} else {
				request = new String(this.requestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
			}

			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + request + (this.requestResponse.request().body().length() == 0 ? "" : "\n\n") + this.responseEditor.getText()), null);
		});

		profileCombo.addActionListener((ActionEvent e) -> {
			this.responseEditor.setText("Running Response Copy Rules...");
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);

			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					String response;
					if (profileCombo.getSelectedItem() != null) {
						CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

						// To save processing time, we combine the Global Profile and Selected Profile into one.
						CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
						ResponseRulesTableModel tempResponseRulesTableModel = (ResponseRulesTableModel) tempProfile.getResponseRulesTableModel();

						for (Rule replacement : globalProfile.getResponseRulesTableModel().getData()) {
							tempResponseRulesTableModel.add(replacement);
						}

						for (Rule replacement : selectedProfile.getResponseRulesTableModel().getData()) {
							tempResponseRulesTableModel.add(replacement);
						}

						response = new String(tempProfile.replace(requestResponse, false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);
						lastRunProfile = selectedProfile;
					} else {
						response = new String(requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
						lastRunProfile = null;
					}
					responseEditor.setText(response);
					responseEditor.setCaretPosition(0);
					copyButton.setEnabled(true);
					copyBothButton.setEnabled(true);
				}
			});
		});

		if (this.requestResponse != null && profileCombo.getItemCount() > 0) {

			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					String response = null;
					if (profileCombo.getSelectedItem() != null) {
						CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();
						if (lastRunProfile == null && !lastRunProfile.equals(selectedProfile)) {

							responseEditor.setText("Running Response Copy Rules...");
							copyButton.setEnabled(false);
							copyBothButton.setEnabled(false);

							// To save processing time, we combine the Global Profile and Selected Profile into one.
							CopyProfile tempProfile = new CopyProfile(selectedProfile.getName());
							ResponseRulesTableModel tempResponseRulesTableModel = (ResponseRulesTableModel) tempProfile.getResponseRulesTableModel();

							for (Rule replacement : globalProfile.getResponseRulesTableModel().getData()) {
								tempResponseRulesTableModel.add(replacement);
							}

							for (Rule replacement : selectedProfile.getResponseRulesTableModel().getData()) {
								tempResponseRulesTableModel.add(replacement);
							}

							response = new String(tempProfile.replace(requestResponse, false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);

							lastRunProfile = selectedProfile;
						}
					}

					if (response == null) {
						response = new String(requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);;
					}

					responseEditor.setText(response);
					responseEditor.setCaretPosition(0);
					copyButton.setEnabled(true);
					copyBothButton.setEnabled(true);
				}
			});
		}

		JScrollPane scrollPane = new JScrollPane(this.responseEditor);
		TextLineNumber tln = new TextLineNumber(this.responseEditor);
		scrollPane.setRowHeaderView(tln);

		this.responseEditor.setCaretPosition(0);

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
			.addComponent(scrollPane)
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
			.addComponent(scrollPane)
		);

		return panel;
	}

	@Override
	public Selection selectedData() {
		return this.responseEditor.getSelectedText().isEmpty() ? Selection.selection(ByteArray.byteArray(this.responseEditor.getSelectedText())) : null;
	}

	@Override
	public boolean isModified() {
		return false;
	}

}

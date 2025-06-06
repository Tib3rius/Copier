package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
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
	private final JTextArea requestEditor;
	private HttpRequestResponse requestResponse;
	private boolean includeURLBoolean = false;

	public CopyRequestEditor(MontoyaApi api, GlobalCopyProfile globalProfile, JComboBox<CopyProfile> profiles, EditorCreationContext creationContext) {
		this.api = api;
		this.globalProfile = globalProfile;
		this.profiles = profiles;
		this.requestEditor = new JTextArea();
		this.requestEditor.setLineWrap(true);
		this.requestEditor.setWrapStyleWord(false);
		this.requestEditor.setFont(api.userInterface().currentEditorFont());
				
		if (creationContext.editorMode() == EditorMode.READ_ONLY) {
			this.requestEditor.setEditable(false);
		}
	}

	@Override
	public HttpRequest getRequest() {
		return this.requestResponse.request();
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse) {
		this.requestResponse = requestResponse;
		this.requestEditor.setText(requestResponse.request().toByteArray().toString());
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
		JPanel panel = new JPanel();
		
		JLabel profileLabel = new JLabel("Profile:");
		profileLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize() + 1));
        profileLabel.setForeground(Copier.FONT_COLOR);
		
		JComboBox<CopyProfile> profileCombo = new JComboBox<>();
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
		
		JButton copyButton = new JButton("Copy Request");
		copyButton.addActionListener((ActionEvent e) -> {
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + this.requestEditor.getText()), null);
		});

		JButton copyBothButton = new JButton("Copy Request + Response");
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

			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.request().url() + "\n\n" : "") + this.requestEditor.getText() + (this.requestResponse.request().body().length() == 0 ? "" : "\n\n") + response), null);
		});

		profileCombo.addActionListener((ActionEvent e) -> {
			this.requestEditor.setText("Running Request Copy Rules...");
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
					requestEditor.setText(request);
					requestEditor.setCaretPosition(0);
					copyButton.setEnabled(true);
					copyBothButton.setEnabled(true);
				}
			});
		});

		// Run Request Copy Rules on UI Load.
		if (this.requestResponse != null && profileCombo.getItemCount() > 0) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					String request = requestEditor.getText();;
					if (profileCombo.getSelectedItem() != null) {
						CopyProfile selectedProfile = (CopyProfile) profileCombo.getSelectedItem();

						requestEditor.setText("Running Request Copy Rules...");
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

					requestEditor.setText(request);
					requestEditor.setCaretPosition(0);
					copyButton.setEnabled(true);
					copyBothButton.setEnabled(true);
				}
			});
		}
		
		JScrollPane scrollPane = new JScrollPane(this.requestEditor);
		TextLineNumber tln = new TextLineNumber(this.requestEditor);
		scrollPane.setRowHeaderView(tln);
		
		this.requestEditor.setCaretPosition(0);
		
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

		panel.repaint();
		
		return panel;
	}

	@Override
	public Selection selectedData() {
		return this.requestEditor.getSelectedText().isEmpty() ? Selection.selection(ByteArray.byteArray(this.requestEditor.getSelectedText())) : null;
	}

	@Override
	public boolean isModified() {
		return false;
	}

}

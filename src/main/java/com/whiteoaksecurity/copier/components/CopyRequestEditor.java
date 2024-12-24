package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.whiteoaksecurity.copier.Copier;
import com.whiteoaksecurity.copier.CopyProfile;
import com.whiteoaksecurity.copier.GlobalCopyProfile;
import com.whiteoaksecurity.copier.Logger;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.lang.Thread;

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
	public void setRequestResponse(HttpRequestResponse requestReponse) {
		this.requestResponse = requestReponse;
		this.requestEditor.setText(requestReponse.request().toByteArray().toString());
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
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.url() + "\n\n" : "") + this.requestEditor.getText()), null);
		});

		JButton copyBothButton = new JButton("Copy Request + Response");
		copyBothButton.addActionListener((ActionEvent e) -> {
			String response;
			if (profileCombo.getSelectedItem() != null) {
				response = new String(((CopyProfile) profileCombo.getSelectedItem())
					.replace(this.globalProfile.replace(this.requestResponse, false, true), false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);
			} else {
				response = new String(this.requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
			}

			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.url() + "\n\n" : "") + this.requestEditor.getText() + (this.requestResponse.request().body().length() == 0 ? "" : "\n\n") + response), null);
		});

		profileCombo.addActionListener((ActionEvent e) -> {
			this.requestEditor.setText("Running Request Copy Rules...");
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);
			(new Thread(() -> {
				String request;
				if (profileCombo.getSelectedItem() != null) {
					request = new String(((CopyProfile) profileCombo.getSelectedItem())
						.replace(this.globalProfile.replace(this.requestResponse, true, false), true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);
				} else {
					request = new String(this.requestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
				}
				this.requestEditor.setText(request);
				this.requestEditor.setCaretPosition(0);
				copyButton.setEnabled(true);
				copyBothButton.setEnabled(true);
			})).start();
		});

		if (this.requestResponse != null && profileCombo.getItemCount() > 0) {
			this.requestEditor.setText("Running Request Copy Rules...");
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);
			(new Thread(() -> {
				String request;
				if (profileCombo.getSelectedItem() != null) {
					request = new String(((CopyProfile) profileCombo.getSelectedItem())
						.replace(this.globalProfile.replace(this.requestResponse, true, false), true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);
				} else {
					request = new String(this.requestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
				}
				this.requestEditor.setText(request);
				this.requestEditor.setCaretPosition(0);
				copyButton.setEnabled(true);
				copyBothButton.setEnabled(true);
			})).start();
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

package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.whiteoaksecurity.copier.Copier;
import com.whiteoaksecurity.copier.CopyProfile;
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

public class CopyResponseEditor implements ExtensionProvidedHttpResponseEditor {
	
	private final MontoyaApi api;
	private final JComboBox<CopyProfile> profiles;
	private final JTextArea responseEditor;
	private HttpRequestResponse requestResponse;
	private boolean includeURLBoolean = false;
	
	public CopyResponseEditor(MontoyaApi api, JComboBox<CopyProfile> profiles, EditorCreationContext creationContext) {
		this.api = api;
		this.profiles = profiles;
		this.responseEditor = new JTextArea();
		this.responseEditor.setLineWrap(true);
		this.responseEditor.setWrapStyleWord(false);
		//this.responseEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
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
	public void setRequestResponse(HttpRequestResponse requestReponse) {
		this.requestResponse = requestReponse;
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
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.url() + "\n\n" : "") + this.responseEditor.getText()), null);
		});
		
		JButton copyBothButton = new JButton("Copy Request + Response");
		copyBothButton.addActionListener((ActionEvent e) -> {
			String request;
			if (profileCombo.getSelectedItem() != null) {
				request = new String(((CopyProfile) profileCombo.getSelectedItem())
					.replace(this.requestResponse, true, false).request().toByteArray().getBytes(), StandardCharsets.UTF_8);
			} else {
				request = new String(this.requestResponse.request().toByteArray().getBytes(), StandardCharsets.UTF_8);
			}
			
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection((this.includeURLBoolean ? this.requestResponse.url() + "\n\n" : "") + request + (this.requestResponse.request().body().length() == 0 ? "" : "\n\n") + this.responseEditor.getText()), null);
		});

		profileCombo.addActionListener((ActionEvent e) -> {
			this.responseEditor.setText("Running Response Copy Rules...");
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);
			(new Thread(() -> {
				String response;
				if (profileCombo.getSelectedItem() != null) {
					response = new String(((CopyProfile) profileCombo.getSelectedItem())
						.replace(this.requestResponse, false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);
				} else {
					response = new String(this.requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
				}
				this.responseEditor.setText(response);
				this.responseEditor.setCaretPosition(0);
				copyButton.setEnabled(true);
				copyBothButton.setEnabled(true);
			})).start();
		});

		if (this.requestResponse != null && profileCombo.getItemCount() > 0) {
			this.responseEditor.setText("Running Response Copy Rules...");
			copyButton.setEnabled(false);
			copyBothButton.setEnabled(false);
			(new Thread(() -> {
				String response;
				if (profileCombo.getSelectedItem() != null) {
					response = new String(((CopyProfile) profileCombo.getSelectedItem())
						.replace(this.requestResponse, false, true).response().toByteArray().getBytes(), StandardCharsets.UTF_8);
				} else {
					response = new String(this.requestResponse.response().toByteArray().getBytes(), StandardCharsets.UTF_8);
				}
				this.responseEditor.setText(response);
				this.responseEditor.setCaretPosition(0);
				copyButton.setEnabled(true);
				copyBothButton.setEnabled(true);
			})).start();
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

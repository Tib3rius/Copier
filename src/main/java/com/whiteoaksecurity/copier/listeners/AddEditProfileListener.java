package com.whiteoaksecurity.copier.listeners;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.whiteoaksecurity.copier.Copier;
import com.whiteoaksecurity.copier.CopyProfile;
import com.whiteoaksecurity.copier.Logger;
import com.whiteoaksecurity.copier.Persistor;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;

public class AddEditProfileListener implements ActionListener {
	private JFrame parent;
	private JComboBox<CopyProfile> profileCombo;	
	private JTable requestTable;
	private JTable responseTable;
	
	public AddEditProfileListener(JFrame parent, JComboBox<CopyProfile> profileCombo, JTable requestTable, JTable responseTable) {
		this.parent = parent;
		this.profileCombo = profileCombo;
		this.requestTable = requestTable;
		this.responseTable = responseTable;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		String title = "";
		String submit = "";

		JTextField profileNameField = new JTextField(20);

		switch (event.getActionCommand()) {
			case "Add" -> {
				title = "Add Profile";
				submit = "Add";
				break;
			}
			case "Edit" -> {
				title = "Edit Profile";
				submit = "Edit";
				profileNameField.setText(((CopyProfile) this.profileCombo.getSelectedItem()).getName());
				break;
			}
			case "Duplicate" -> {
				title = "Duplicate Profile";
				submit = "Duplicate";
				profileNameField.setText(((CopyProfile) this.profileCombo.getSelectedItem()).getName());
				break;
			}
		}

		JDialog profileDialog = new JDialog(this.parent, title, true);
		profileDialog.setResizable(false);
		JPanel profilePanel = new JPanel();
		GroupLayout layout = new GroupLayout(profilePanel);

		JLabel profileNameLabel = new JLabel("Profile Name:");
		JLabel profileNameErrorLabel = new JLabel();
		profileNameErrorLabel.setForeground(Color.RED);

		JButton submitButton = new JButton(submit);
		submitButton.addActionListener((ActionEvent e) -> {
			if (profileNameField.getText().strip().length() == 0) {
				profileNameErrorLabel.setText("Profile name cannot be empty!");
				profileDialog.pack();
			} else {
				// Check that a profile with the same name doesn't already exist.
				boolean duplicate = false;

				// If we're editing we only need to do this if we've changed the name.
				if (event.getActionCommand().equals("Duplicate") || (event.getActionCommand().equals("Edit") && !((CopyProfile) this.profileCombo.getSelectedItem()).getName().equals(profileNameField.getText()))) {
					int size = this.profileCombo.getItemCount();
					for (int i = 0; i < size; i++) {
						if (this.profileCombo.getItemAt(i).getName().equals(profileNameField.getText())) {
							duplicate = true;
							profileNameErrorLabel.setText("Profile name already exists!");
							profileDialog.pack();
							break;
						}
					}
				}

				if (!duplicate) {
					switch (event.getActionCommand()) {
						case "Add" -> {
							CopyProfile cp = new CopyProfile(profileNameField.getText());
							this.profileCombo.addItem(cp);
							this.profileCombo.setSelectedItem(cp);
							Copier.resizeColumnWidth(requestTable);
							Copier.resizeColumnWidth(responseTable);
							Persistor.getPersistor().save();
							break;
						}
						case "Edit" -> {
							((CopyProfile) this.profileCombo.getSelectedItem()).setName(profileNameField.getText());
							Persistor.getPersistor().save();
							break;
						}
						case "Duplicate" -> {
							ObjectMapper objectMapper = new ObjectMapper();
							objectMapper.registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES));
							try {
								String json = objectMapper.writeValueAsString((CopyProfile) this.profileCombo.getSelectedItem());
								CopyProfile dupe = objectMapper.readValue(json, new TypeReference<CopyProfile>(){});
								dupe.setName(profileNameField.getText());
								this.profileCombo.addItem(dupe);
								this.profileCombo.setSelectedItem(dupe);
								Copier.resizeColumnWidth(requestTable);
								Copier.resizeColumnWidth(responseTable);
								Persistor.getPersistor().save();
							} catch (JsonProcessingException ex) {
								Logger.getLogger().logToError(ex.getMessage());
							} catch (IOException ex) {
								Logger.getLogger().logToError(ex.getMessage());
							}
							break;
						}

					}

					profileDialog.dispose();
				}
			}
		});

		JButton cancelButton = new JButton("Cancel");
		cancelButton.addActionListener((ActionEvent e) -> {
			profileDialog.dispose();
		});


		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);
		profilePanel.setLayout(layout);

		layout.setHorizontalGroup(layout.createSequentialGroup()
			.addGap(15)
			.addComponent(profileNameLabel)
			.addGroup(layout.createParallelGroup()
				.addComponent(profileNameField)
				.addGroup(layout.createSequentialGroup()
					.addComponent(submitButton)
					.addComponent(cancelButton)
				)
				.addComponent(profileNameErrorLabel)
			)

			.addGap(15)
		);

		layout.setVerticalGroup(layout.createSequentialGroup()
			.addGap(15)
			.addGroup(layout.createParallelGroup()
				.addComponent(profileNameLabel)
				.addComponent(profileNameField)
			)
			.addGroup(layout.createParallelGroup()
				.addComponent(submitButton)
				.addComponent(cancelButton)
			)
			.addComponent(profileNameErrorLabel)
			.addGap(15)
		);

		profileDialog.getContentPane().add(profilePanel);
		profileDialog.pack();

		profileDialog.setMinimumSize(new Dimension(profileDialog.getPreferredSize().width, profileDialog.getPreferredSize().height));
		profileDialog.setLocationRelativeTo(parent);
		profileDialog.setVisible(true);
	}
}
	
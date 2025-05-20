package com.whiteoaksecurity.copier;
import com.fasterxml.jackson.databind.JsonNode;
import com.whiteoaksecurity.copier.components.CopyRequestEditorProvider;
import com.whiteoaksecurity.copier.components.CopyContextMenu;
import com.whiteoaksecurity.copier.components.CopyResponseEditorProvider;
import com.whiteoaksecurity.copier.models.RulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.listeners.ProfileComboActionListener;
import com.whiteoaksecurity.copier.listeners.AddEditProfileListener;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.annotation.JsonCreator.Mode;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.whiteoaksecurity.copier.listeners.AddEditRuleListener;
import com.whiteoaksecurity.copier.listeners.DeleteProfileListener;
import com.whiteoaksecurity.copier.listeners.DeleteRuleListener;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

public class Copier implements BurpExtension {

	GlobalCopyProfile globalProfile;
	JTable globalRequestRulesTable;
	JTable globalResponseRulesTable;
	JComboBox<CopyProfile> profiles;
	public final static Color FONT_COLOR = new Color(0xE58925);

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Copier");
		
		new Logger(api.logging());
		new Persistor(api);

		ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
		objectMapper.registerModule(new ParameterNamesModule(Mode.PROPERTIES));

		// Suite Tab
		JScrollPane suiteTab = new JScrollPane(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		
		JFrame parent = (JFrame) api.userInterface().swingUtils().suiteFrame();
		
		// Main Layout
		JPanel mainPanel = new JPanel();
		suiteTab.setViewportView(mainPanel);
		
		GroupLayout mainLayout = new GroupLayout(mainPanel);
		mainLayout.setAutoCreateGaps(true);
		mainLayout.setAutoCreateContainerGaps(true);
		mainPanel.setLayout(mainLayout);
		
		JLabel titleLabel = new JLabel("Copier Settings");			
		
        titleLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize() + 2));
        titleLabel.setForeground(FONT_COLOR);
		
		JTabbedPane tabs = new JTabbedPane();

		JSeparator authorSeparator = new JSeparator();
		authorSeparator.setBackground(FONT_COLOR);
		JLabel authorLabel = new JLabel("Copier was created by Tib3rius & White Oak Security.");
		
		mainLayout.setHorizontalGroup(mainLayout.createParallelGroup()
			.addGroup(mainLayout.createSequentialGroup()
				.addGap(15)
				.addComponent(titleLabel)
			)
			.addComponent(tabs)
			.addComponent(authorSeparator)
			.addComponent(authorLabel)
		);
		
		mainLayout.setVerticalGroup(mainLayout.createSequentialGroup()
			.addGap(15)
			.addComponent(titleLabel)
			.addGap(15)
			.addComponent(tabs)
			.addGap(15)
			.addComponent(authorSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
			.addGap(10)
			.addComponent(authorLabel)
			.addContainerGap()
		);

		// Global Profile Layout
		JPanel globalProfilePanel = new JPanel(true);

		GroupLayout globalProfileLayout = new GroupLayout(globalProfilePanel);
		globalProfileLayout.setAutoCreateGaps(true);
		globalProfileLayout.setAutoCreateContainerGaps(true);
		globalProfilePanel.setLayout(globalProfileLayout);

		JLabel globalRequestRulesLabel = new JLabel("Request Copy Rules");
		globalRequestRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));

		RequestRulesTableModel globalRequestRulesTableModel = new RequestRulesTableModel();
		this.globalRequestRulesTable = new JTable(globalRequestRulesTableModel);
		this.globalRequestRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		JScrollPane globalRequestRulesTableScrollPane = new JScrollPane(this.globalRequestRulesTable);
		AddEditRuleListener globalRequestRuleListener = new AddEditRuleListener(parent, this.globalRequestRulesTable);

		// Add Request Rule
		JButton globalAddRequestRuleButton = new JButton("Add");
		globalAddRequestRuleButton.setActionCommand("Add");
		globalAddRequestRuleButton.addActionListener(globalRequestRuleListener);

		JButton globalEditRequestRuleButton = new JButton("Edit");
		globalEditRequestRuleButton.setActionCommand("Edit");
		globalEditRequestRuleButton.addActionListener(globalRequestRuleListener);

		JButton globalDeleteRequestRuleButton = new JButton("Delete");
		globalDeleteRequestRuleButton.addActionListener(new DeleteRuleListener(parent, this.globalRequestRulesTable));

		JButton globalUpRequestRuleButton = new JButton("Up");
		globalUpRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = this.globalRequestRulesTable.getSelectedRow();
			if (selectedRow > 0) {

				RulesTableModel model = (RequestRulesTableModel) this.globalRequestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				this.globalRequestRulesTable.repaint();
				this.globalRequestRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
				Persistor.getPersistor().save();
			}
		});

		JButton globalDownRequestRuleButton = new JButton("Down");
		globalDownRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = this.globalRequestRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < this.globalRequestRulesTable.getModel().getRowCount() - 1) {

				RulesTableModel model = (RequestRulesTableModel) this.globalRequestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				this.globalRequestRulesTable.repaint();
				this.globalRequestRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
				Persistor.getPersistor().save();
			}
		});

		JCheckBox globalUpdateRequestContentLengthCheckBox = new JCheckBox("Update request Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		globalUpdateRequestContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			this.globalProfile.setUpdateRequestContentLength(globalUpdateRequestContentLengthCheckBox.isSelected());
			Persistor.getPersistor().save();
		}));

		ResponseRulesTableModel globalResponseRulesTableModel = new ResponseRulesTableModel();
		this.globalResponseRulesTable = new JTable(globalResponseRulesTableModel);
		this.globalResponseRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		JScrollPane globalResponseRulesTableScrollPane = new JScrollPane(this.globalResponseRulesTable);
		AddEditRuleListener globalResponseRuleListener = new AddEditRuleListener(parent, this.globalResponseRulesTable);

		JLabel globalResponseRulesLabel = new JLabel("Response Copy Rules");
		globalResponseRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));

		JButton globalAddResponseRuleButton = new JButton("Add");
		globalAddResponseRuleButton.setActionCommand("Add");
		globalAddResponseRuleButton.addActionListener(globalResponseRuleListener);

		JButton globalEditResponseRuleButton = new JButton("Edit");
		globalEditResponseRuleButton.setActionCommand("Edit");
		globalEditResponseRuleButton.addActionListener(globalResponseRuleListener);

		JButton globalDeleteResponseRuleButton = new JButton("Delete");
		globalDeleteResponseRuleButton.addActionListener(new DeleteRuleListener(parent, this.globalResponseRulesTable));

		JButton globalUpResponseRuleButton = new JButton("Up");
		globalUpResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = this.globalResponseRulesTable.getSelectedRow();
			if (selectedRow > 0) {

				RulesTableModel model = (ResponseRulesTableModel) this.globalResponseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				this.globalResponseRulesTable.repaint();
				this.globalResponseRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
				Persistor.getPersistor().save();
			}
		});

		JButton globalDownResponseRuleButton = new JButton("Down");
		globalDownResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = this.globalResponseRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < this.globalResponseRulesTable.getModel().getRowCount() - 1) {

				RulesTableModel model = (ResponseRulesTableModel) this.globalResponseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				this.globalResponseRulesTable.repaint();
				this.globalResponseRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
				Persistor.getPersistor().save();
			}
		});

		JCheckBox globalUpdateResponseContentLengthCheckBox = new JCheckBox("Update response Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		globalUpdateResponseContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			this.globalProfile.setUpdateResponseContentLength(globalUpdateResponseContentLengthCheckBox.isSelected());
			Persistor.getPersistor().save();
		}));

		globalProfileLayout.setHorizontalGroup(globalProfileLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(globalProfileLayout.createParallelGroup()
				.addComponent(globalRequestRulesLabel)
					.addGroup(globalProfileLayout.createSequentialGroup()
						.addGroup(globalProfileLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
							.addComponent(globalAddRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalEditRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalDeleteRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalUpRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalDownRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						)
						.addComponent(globalRequestRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
					)
					.addComponent(globalUpdateRequestContentLengthCheckBox)
					.addComponent(globalResponseRulesLabel)
					.addGroup(globalProfileLayout.createSequentialGroup()
						.addGroup(globalProfileLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
							.addComponent(globalAddResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalEditResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalDeleteResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalUpResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(globalDownResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						)
						.addComponent(globalResponseRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
					)
					.addComponent(globalUpdateResponseContentLengthCheckBox)
				)
				.addGap(15)
		);

		globalProfileLayout.setVerticalGroup(globalProfileLayout.createSequentialGroup()
			.addGap(15)
			.addComponent(globalRequestRulesLabel)
			.addGap(10)
			.addGroup(globalProfileLayout.createParallelGroup()
				.addGroup(globalProfileLayout.createSequentialGroup()
					.addComponent(globalAddRequestRuleButton)
					.addComponent(globalEditRequestRuleButton)
					.addComponent(globalDeleteRequestRuleButton)
					.addComponent(globalUpRequestRuleButton)
					.addComponent(globalDownRequestRuleButton)
				)
				.addComponent(globalRequestRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(globalUpdateRequestContentLengthCheckBox)
			.addGap(15)
			.addComponent(globalResponseRulesLabel)
			.addGap(10)
			.addGroup(globalProfileLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				.addGroup(globalProfileLayout.createSequentialGroup()
					.addComponent(globalAddResponseRuleButton)
					.addComponent(globalEditResponseRuleButton)
					.addComponent(globalDeleteResponseRuleButton)
					.addComponent(globalUpResponseRuleButton)
					.addComponent(globalDownResponseRuleButton)
				)
				.addComponent(globalResponseRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(globalUpdateResponseContentLengthCheckBox)
		);

		// Profile Layout
        JPanel profilesPanel = new JPanel(true);
		
        GroupLayout profilesLayout = new GroupLayout(profilesPanel);
        profilesLayout.setAutoCreateGaps(true);
        profilesLayout.setAutoCreateContainerGaps(true);
		profilesPanel.setLayout(profilesLayout);
		
		JLabel profileLabel = new JLabel("Profile:");
		profileLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize()));
		
		this.profiles = new JComboBox<>();
		this.profiles.setMinimumSize(new Dimension(200, this.profiles.getPreferredSize().height));
		this.profiles.setMaximumSize(this.profiles.getPreferredSize());
		
		JButton addProfileButton = new JButton("Add");
		addProfileButton.setActionCommand("Add");
		
		JButton editProfileButton = new JButton("Edit");
		editProfileButton.setActionCommand("Edit");
		
		JButton deleteProfileButton = new JButton("Delete");
		deleteProfileButton.addActionListener(new DeleteProfileListener(parent, this.profiles));
		
		JButton duplicateProfileButton = new JButton("Duplicate");
		duplicateProfileButton.setActionCommand("Duplicate");
		
		JLabel requestRulesLabel = new JLabel("Request Copy Rules");
		requestRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));
		
		RequestRulesTableModel requestRulesTableModel = new RequestRulesTableModel();
		JTable requestRulesTable = new JTable(requestRulesTableModel);
		requestRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		
		JScrollPane requestRulesTableScrollPane = new JScrollPane(requestRulesTable);
		AddEditRuleListener requestRuleListener = new AddEditRuleListener(parent, requestRulesTable);
		
		// Add Request Rule
		JButton addRequestRuleButton = new JButton("Add");
		addRequestRuleButton.setActionCommand("Add");
		addRequestRuleButton.addActionListener(requestRuleListener);
		
		JButton editRequestRuleButton = new JButton("Edit");
		editRequestRuleButton.setActionCommand("Edit");
		editRequestRuleButton.addActionListener(requestRuleListener);
		
		JButton deleteRequestRuleButton = new JButton("Delete");
		deleteRequestRuleButton.addActionListener(new DeleteRuleListener(parent, requestRulesTable));
		
		JButton upRequestRuleButton = new JButton("Up");
		upRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = requestRulesTable.getSelectedRow();
			if (selectedRow > 0) {
				
				RulesTableModel model = (RequestRulesTableModel) requestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				requestRulesTable.repaint();
				requestRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
				Persistor.getPersistor().save();
			}
		});
		
		JButton downRequestRuleButton = new JButton("Down");
		downRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = requestRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < requestRulesTable.getModel().getRowCount() - 1) {
				
				RulesTableModel model = (RequestRulesTableModel) requestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				requestRulesTable.repaint();
				requestRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
				Persistor.getPersistor().save();
			}
		});
		
		JCheckBox updateRequestContentLengthCheckBox = new JCheckBox("Update request Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		updateRequestContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			((CopyProfile) this.profiles.getSelectedItem()).setUpdateRequestContentLength(updateRequestContentLengthCheckBox.isSelected());
			Persistor.getPersistor().save();
		}));
		
		ResponseRulesTableModel responseRulesTableModel = new ResponseRulesTableModel();
		JTable responseRulesTable = new JTable(responseRulesTableModel);
		responseRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
				
		JScrollPane responseRulesTableScrollPane = new JScrollPane(responseRulesTable);
		AddEditRuleListener responseRuleListener = new AddEditRuleListener(parent, responseRulesTable);
		
		JLabel responseRulesLabel = new JLabel("Response Copy Rules");
		responseRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));

		JButton addResponseRuleButton = new JButton("Add");
		addResponseRuleButton.setActionCommand("Add");
		addResponseRuleButton.addActionListener(responseRuleListener);
		
		JButton editResponseRuleButton = new JButton("Edit");
		editResponseRuleButton.setActionCommand("Edit");
		editResponseRuleButton.addActionListener(responseRuleListener);
		
		JButton deleteResponseRuleButton = new JButton("Delete");
		deleteResponseRuleButton.addActionListener(new DeleteRuleListener(parent, responseRulesTable));
		
		JButton upResponseRuleButton = new JButton("Up");
		upResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = responseRulesTable.getSelectedRow();
			if (selectedRow > 0) {
				
				RulesTableModel model = (ResponseRulesTableModel) responseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				responseRulesTable.repaint();
				responseRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
				Persistor.getPersistor().save();
			}
		});
		
		JButton downResponseRuleButton = new JButton("Down");
		downResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = responseRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < responseRulesTable.getModel().getRowCount() - 1) {
				
				RulesTableModel model = (ResponseRulesTableModel) responseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				responseRulesTable.repaint();
				responseRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
				Persistor.getPersistor().save();
			}
		});
		
		JCheckBox updateResponseContentLengthCheckBox = new JCheckBox("Update response Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		updateResponseContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			((CopyProfile) this.profiles.getSelectedItem()).setUpdateResponseContentLength(updateResponseContentLengthCheckBox.isSelected());
			Persistor.getPersistor().save();
		}));
		
		AddEditProfileListener profileListener = new AddEditProfileListener(parent, this.profiles, requestRulesTable, responseRulesTable);
		addProfileButton.addActionListener(profileListener);
		editProfileButton.addActionListener(profileListener);
		duplicateProfileButton.addActionListener(profileListener);

		this.profiles.addActionListener(new ProfileComboActionListener(requestRulesTable, updateRequestContentLengthCheckBox, responseRulesTable, updateResponseContentLengthCheckBox));
		
		profilesLayout.setHorizontalGroup(profilesLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(profilesLayout.createParallelGroup()
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(profileLabel)
					.addComponent(this.profiles)
					.addComponent(addProfileButton)
					.addComponent(editProfileButton)
					.addComponent(duplicateProfileButton)
					.addComponent(deleteProfileButton)
				)
				.addComponent(requestRulesLabel)
				.addGroup(profilesLayout.createSequentialGroup()
					.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
						.addComponent(addRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(editRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(deleteRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(upRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(downRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					)
					.addComponent(requestRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
				)
				.addComponent(updateRequestContentLengthCheckBox)
				.addComponent(responseRulesLabel)
				.addGroup(profilesLayout.createSequentialGroup()
					.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
						.addComponent(addResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(editResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(deleteResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(upResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(downResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					)
					.addComponent(responseRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
				)
				.addComponent(updateResponseContentLengthCheckBox)
			)
			.addGap(15)
		);
		
		profilesLayout.setVerticalGroup(profilesLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				.addComponent(profileLabel)
				.addComponent(this.profiles)
				.addComponent(addProfileButton)
				.addComponent(editProfileButton)
				.addComponent(duplicateProfileButton)
				.addComponent(deleteProfileButton)
			)
			.addGap(15)
			.addComponent(requestRulesLabel)
			.addGap(10)
			.addGroup(profilesLayout.createParallelGroup()
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(addRequestRuleButton)
					.addComponent(editRequestRuleButton)
					.addComponent(deleteRequestRuleButton)
					.addComponent(upRequestRuleButton)
					.addComponent(downRequestRuleButton)
				)
				.addComponent(requestRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(updateRequestContentLengthCheckBox)
			.addGap(15)
			.addComponent(responseRulesLabel)
			.addGap(10)
			.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(addResponseRuleButton)
					.addComponent(editResponseRuleButton)
					.addComponent(deleteResponseRuleButton)
					.addComponent(upResponseRuleButton)
					.addComponent(downResponseRuleButton)
				)
				.addComponent(responseRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(updateResponseContentLengthCheckBox)
		);

		// Persistence
		JPanel settingsPanel = new JPanel(true);

		GroupLayout settingsLayout = new GroupLayout(settingsPanel);
		settingsLayout.setAutoCreateGaps(true);
		settingsLayout.setAutoCreateContainerGaps(true);
		settingsPanel.setLayout(settingsLayout);

		JLabel resetLabel = new JLabel("Clear all profiles.");
		JButton resetButton = new JButton("Clear");
		resetButton.addActionListener((ActionEvent e) -> {
			int answer = JOptionPane.showConfirmDialog(parent,
					"Clear Profiles?",
					"Do you want to clear all profiles? This action is irreversible. Consider exporting profiles first!",
					JOptionPane.YES_NO_OPTION
			);
			if (answer == JOptionPane.YES_OPTION) {
				((RequestRulesTableModel) this.globalRequestRulesTable.getModel()).clear();
				((ResponseRulesTableModel) this.globalResponseRulesTable.getModel()).clear();
				this.profiles.removeAllItems();
				this.profiles.addItem(new CopyProfile("Default"));
				// Set Request Table Column Widths
				resizeColumnWidth(requestRulesTable);

				// Set Response Table Column Widths
				resizeColumnWidth(responseRulesTable);

				Persistor.getPersistor().save();
			}
		});

		JLabel exportLabel = new JLabel("Export the current profiles to a JSON file.");
		JButton exportButton = new JButton("Export");
		exportButton.addActionListener((ActionEvent e) -> {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Export Copy Profiles to File");

			int userSelection = fileChooser.showSaveDialog(parent);

			if (userSelection == JFileChooser.APPROVE_OPTION) {
				File exportFile = fileChooser.getSelectedFile();
				try {
					BufferedWriter writer = new BufferedWriter(new FileWriter(exportFile));
					Map<String, Object> jsonMap = new LinkedHashMap<>();

					jsonMap.put("version", "2");

					jsonMap.put("globalProfile", globalProfile);

					CopyProfile[] profileArray = new CopyProfile[this.profiles.getItemCount()];
					for (int i = 0; i < this.profiles.getItemCount(); i++) {
						profileArray[i] = this.profiles.getItemAt(i);
					}
					jsonMap.put("profiles", profileArray);

					writer.write(objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(jsonMap));
					writer.flush();
					writer.close();
				} catch (JsonProcessingException ex) {
					api.logging().logToError(ex.getMessage());
				} catch (IOException ex) {
					api.logging().logToError(ex.getMessage());
				}
			}
		});

		JLabel importLabel = new JLabel("Import profiles from a JSON file.");
		JButton importButton = new JButton("Import");
		importButton.addActionListener((ActionEvent e) -> {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Import Copy Profiles from File");

			int userSelection = fileChooser.showOpenDialog(parent);

			if (userSelection == JFileChooser.APPROVE_OPTION) {
				File importFile = fileChooser.getSelectedFile();
				try {
					StringBuilder sb = new StringBuilder();
					BufferedReader br = new BufferedReader(new FileReader(importFile));
					String line;
					while ((line = br.readLine()) != null) {
						sb.append(line).append("\n");
					}
					br.close();

					JsonNode json = objectMapper.readTree(sb.toString());

					if (json.has("version") && json.get("version").asText().equals("2")) {
						Logger.getLogger().logToOutput("Copier v2 Preferences Found");
						if (json.has("globalProfile")) {
							this.globalProfile = objectMapper.convertValue(json.get("globalProfile"), new TypeReference<GlobalCopyProfile>() {
							});

							this.globalRequestRulesTable.setModel(this.globalProfile.getRequestRulesTableModel());
							globalUpdateRequestContentLengthCheckBox.setSelected(this.globalProfile.getUpdateRequestContentLength());
							this.globalResponseRulesTable.setModel(this.globalProfile.getResponseRulesTableModel());
							globalUpdateResponseContentLengthCheckBox.setSelected(this.globalProfile.getUpdateResponseContentLength());

							Persistor.getPersistor().setGlobalCopyProfile(this.globalProfile);

							// Set Request Table Column Widths
							resizeColumnWidth(this.globalRequestRulesTable);

							// Set Response Table Column Widths
							resizeColumnWidth(this.globalResponseRulesTable);
						}

						if (json.has("profiles")) {
							List<CopyProfile> profileList = objectMapper.convertValue(json.get("profiles"), new TypeReference<List<CopyProfile>>() {
							});
							this.profiles.removeAllItems();

							for (CopyProfile c : profileList) {
								this.profiles.addItem(c);
							}

							Persistor.getPersistor().setCopyProfiles(this.profiles);

							// Set Request Table Column Widths
							resizeColumnWidth(requestRulesTable);

							// Set Response Table Column Widths
							resizeColumnWidth(responseRulesTable);
						}

						Persistor.getPersistor().save();
					} else {
						Logger.getLogger().logToOutput("Copier v1 Preferences Found");

						List<CopyProfile> profileList = objectMapper.readValue(sb.toString(), new TypeReference<List<CopyProfile>>(){});
						this.profiles.removeAllItems();

						for (CopyProfile c : profileList) {
							this.profiles.addItem(c);
						}

						Persistor.getPersistor().save();
					}
				}
				catch (IOException ex) {
					api.logging().logToError(ex.getMessage());
				}
				catch (Exception ex) {
					for (StackTraceElement a : ex.getStackTrace())
					{
						api.logging().logToError(a.toString());
					}
				}
			}
		});

		settingsLayout.setHorizontalGroup(settingsLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(settingsLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
					.addComponent(resetButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(exportButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(importButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
			)
			.addGroup(settingsLayout.createParallelGroup()
					.addComponent(resetLabel)
					.addComponent(exportLabel)
					.addComponent(importLabel)
			)
		);

		settingsLayout.setVerticalGroup(profilesLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(settingsLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
				.addGroup(settingsLayout.createSequentialGroup()
						.addComponent(resetButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(exportButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(importButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				)
				.addGroup(settingsLayout.createSequentialGroup()
						.addComponent(resetLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(exportLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(importLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				)
			)
		);

		tabs.add("Global Profile", globalProfilePanel);
		tabs.addTab("Profiles", profilesPanel);
		tabs.addTab("Export / Import", settingsPanel);

		// Load Global Profile From Saved Preferences
		String preferenceGlobalProfile = api.persistence().preferences().getString("GlobalCopyProfile");
		if (preferenceGlobalProfile != null) {
			api.logging().logToOutput("Loading Global Copy Profile from Saved Preferences.");
			try {
				this.globalProfile = objectMapper.readValue(preferenceGlobalProfile, new TypeReference<GlobalCopyProfile>(){});
			} catch (IOException ex) {
				api.logging().logToError(ex.getMessage());
			}
		}

		// If there is no Global Copy Profile, create one.
		if (this.globalProfile == null) {
			this.globalProfile = new GlobalCopyProfile();
		}

		// Load Rules into Table
		this.globalRequestRulesTable.setModel(this.globalProfile.getRequestRulesTableModel());
		this.globalResponseRulesTable.setModel(this.globalProfile.getResponseRulesTableModel());

		// Set Request Table Column Widths
		resizeColumnWidth(this.globalRequestRulesTable);

		// Set Response Table Column Widths
		resizeColumnWidth(this.globalResponseRulesTable);

		// Load Profiles From Saved Preferences
		String preferenceProfiles = api.persistence().preferences().getString("CopyProfiles");
		if (preferenceProfiles != null) {
			api.logging().logToOutput("Loading Copy Profiles from Saved Preferences.");
			try {
				JsonNode json = objectMapper.readTree(preferenceProfiles);
				// Check if older preference settings are being used.
				if (json.has("version") && json.get("version").asText().equals("2")) {
					Logger.getLogger().logToOutput("Copier v2 Preferences Found");

					if (json.has("globalProfile")) {
						this.globalProfile = objectMapper.convertValue(json.get("globalProfile"), new TypeReference<GlobalCopyProfile>(){});

						this.globalRequestRulesTable.setModel(this.globalProfile.getRequestRulesTableModel());
						globalUpdateRequestContentLengthCheckBox.setSelected(this.globalProfile.getUpdateRequestContentLength());
						this.globalResponseRulesTable.setModel(this.globalProfile.getResponseRulesTableModel());
						globalUpdateResponseContentLengthCheckBox.setSelected(this.globalProfile.getUpdateResponseContentLength());

						// Set Request Table Column Widths
						resizeColumnWidth(this.globalRequestRulesTable);

						// Set Response Table Column Widths
						resizeColumnWidth(this.globalResponseRulesTable);
					}

					if (json.has("profiles")) {
						List<CopyProfile> profileList = objectMapper.convertValue(json.get("profiles"), new TypeReference<List<CopyProfile>>(){});
						this.profiles.removeAllItems();

						for (CopyProfile c : profileList) {
							this.profiles.addItem(c);
						}

						// Set Request Table Column Widths
						resizeColumnWidth(requestRulesTable);

						// Set Response Table Column Widths
						resizeColumnWidth(responseRulesTable);
					}

				} else {
					Logger.getLogger().logToOutput("Copier v1 Preferences Found");

					List<CopyProfile> profileList = objectMapper.readValue(preferenceProfiles, new TypeReference<List<CopyProfile>>(){});
					for (CopyProfile c : profileList) {
						this.profiles.addItem(c);
					}
				}
			} catch (IOException ex) {
				api.logging().logToError(ex.getMessage());
			}
		}
		
		// If there are no Copy Profiles, create a Default one.
		if (this.profiles.getItemCount() == 0) {
			this.profiles.addItem(new CopyProfile("Default"));
		}
		
		// Load Rules from the first Copy Profile.
		this.profiles.setSelectedIndex(0);
		requestRulesTable.setModel(((CopyProfile) this.profiles.getItemAt(0)).getRequestRulesTableModel());
		responseRulesTable.setModel(((CopyProfile) this.profiles.getItemAt(0)).getResponseRulesTableModel());
		
		// Set Request Table Column Widths
		resizeColumnWidth(requestRulesTable);
		
		// Set Response Table Column Widths
		resizeColumnWidth(responseRulesTable);

		// Add Profiles to Persistor & Save (in case of version change).
		Persistor.getPersistor().setGlobalCopyProfile(this.globalProfile);
		Persistor.getPersistor().setCopyProfiles(this.profiles);
		Persistor.getPersistor().save();
		
		api.userInterface().applyThemeToComponent(suiteTab);
		api.userInterface().registerSuiteTab("Copier", suiteTab);
		api.userInterface().registerContextMenuItemsProvider(new CopyContextMenu(api, this.globalProfile, this.profiles));
		
		api.userInterface().registerHttpRequestEditorProvider(new CopyRequestEditorProvider(api, this.globalProfile, this.profiles));
		api.userInterface().registerHttpResponseEditorProvider(new CopyResponseEditorProvider(api, this.globalProfile, this.profiles));
    }
	
	public static void resizeColumnWidth(JTable table) {
		TableColumnModel columnModel = table.getColumnModel();
		// Enabled Column
		columnModel.getColumn(0).sizeWidthToFit();
		columnModel.getColumn(0).setResizable(false);
		
		// Location Column
		columnModel.getColumn(1).setPreferredWidth(175);
		
		// Match Column
		columnModel.getColumn(2).setPreferredWidth(200);
		
		// Replace Column
		columnModel.getColumn(3).setPreferredWidth(200);
		
		// Type Column
		columnModel.getColumn(4).setPreferredWidth(columnModel.getColumn(0).getPreferredWidth());
		columnModel.getColumn(4).setResizable(false);
		DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
		centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
		columnModel.getColumn(4).setCellRenderer(centerRenderer);
		
		// Case Sensitive Column
		columnModel.getColumn(5).setPreferredWidth(115);
		columnModel.getColumn(5).setResizable(false);
		
		// Comment Column
		columnModel.getColumn(6).setPreferredWidth(350);
	}
}
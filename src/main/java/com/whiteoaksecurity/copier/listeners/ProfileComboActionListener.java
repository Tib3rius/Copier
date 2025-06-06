package com.whiteoaksecurity.copier.listeners;

import com.whiteoaksecurity.copier.Copier;
import com.whiteoaksecurity.copier.CopyProfile;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JTable;

public class ProfileComboActionListener implements ActionListener {

	private JCheckBox skipGlobalRulesCheckBox;
	private JTable requestRulesTable;
	private JCheckBox updateRequestContentLengthCheckBox;
	private JTable responseRulesTable;
	private JCheckBox updateResponseContentLengthCheckBox;

	public ProfileComboActionListener(JCheckBox skipGlobalRulesCheckBox, JTable requestRulesTable, JCheckBox updateRequestContentLengthCheckBox, JTable responseRulesTable, JCheckBox updateResponseContentLengthCheckBox)
	{
		this.skipGlobalRulesCheckBox = skipGlobalRulesCheckBox;
		this.requestRulesTable = requestRulesTable;
		this.responseRulesTable = responseRulesTable;
		this.updateRequestContentLengthCheckBox = updateRequestContentLengthCheckBox;
		this.updateResponseContentLengthCheckBox = updateResponseContentLengthCheckBox;
	}
	
	@Override
	public void actionPerformed(ActionEvent event) {
		if ("comboBoxChanged".equals(event.getActionCommand())) {
			CopyProfile profile = (CopyProfile)((JComboBox) event.getSource()).getSelectedItem();
			if (profile != null) {
				skipGlobalRulesCheckBox.setSelected(profile.getSkipGlobalRules());
				requestRulesTable.setModel(profile.getRequestRulesTableModel());
				updateRequestContentLengthCheckBox.setSelected(profile.getUpdateRequestContentLength());
				responseRulesTable.setModel(profile.getResponseRulesTableModel());
				updateResponseContentLengthCheckBox.setSelected(profile.getUpdateResponseContentLength());
				
				Copier.resizeColumnWidth(requestRulesTable);
				Copier.resizeColumnWidth(responseRulesTable);
			}
		}
	}
	
}

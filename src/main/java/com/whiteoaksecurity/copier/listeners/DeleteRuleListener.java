package com.whiteoaksecurity.copier.listeners;

import com.whiteoaksecurity.copier.Persistor;
import com.whiteoaksecurity.copier.models.RulesTableModel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTable;

public class DeleteRuleListener implements ActionListener  {

	private JFrame parent;
	private JTable table;
	private boolean isDialogOpen;
	
	public DeleteRuleListener(JFrame parent, JTable table) {
		this.parent = parent;
		this.table = table;
		this.isDialogOpen = false;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		int rows = this.table.getSelectedRowCount();
		if (rows != 0 && !this.isDialogOpen)
		{
			this.isDialogOpen = true;
			String rule = "Rule";
			if (rows > 1) {
				rule = "Rules";
			}

			String[] options = {"No", "Yes"};
			int decision = JOptionPane.showOptionDialog(
				this.parent,
				"Are you sure you want to delete the selected " + rule.toLowerCase() + "?",
				"Delete " + rule + "?",
				JOptionPane.YES_NO_OPTION,
				JOptionPane.WARNING_MESSAGE,
				null,
				options,
				options[1]
			);

			if (decision ==  1) {
				for (int i = this.table.getSelectedRows().length - 1; i >= 0; i--) {
					((RulesTableModel) this.table.getModel()).getData().remove(this.table.getSelectedRows()[i]);
				}

				Persistor.getPersistor().save();
				
				((RulesTableModel) this.table.getModel()).fireTableDataChanged();
				this.table.repaint();
			}

			this.isDialogOpen = false;
		}
	}
}

	
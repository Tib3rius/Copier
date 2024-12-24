package com.whiteoaksecurity.copier.listeners;

import com.whiteoaksecurity.copier.CopyProfile;
import com.whiteoaksecurity.copier.Persistor;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class DeleteProfileListener implements ActionListener {
	private JFrame parent;
	private JComboBox<CopyProfile> profileCombo;
	private boolean isDialogOpen;
	
	public DeleteProfileListener(JFrame parent, JComboBox<CopyProfile> profileCombo) {
		this.parent = parent;
		this.profileCombo = profileCombo;
		this.isDialogOpen = false;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		if (!this.isDialogOpen) {
			this.isDialogOpen = true;
			
			if (this.profileCombo.getItemCount() == 1) {
				JOptionPane.showMessageDialog(this.parent, "You can't delete the last profile!", "Error!", JOptionPane.ERROR_MESSAGE);
				this.isDialogOpen = false;
			} else {
				String[] options = {"No", "Yes"};
				int decision = JOptionPane.showOptionDialog(
					this.parent,
					"Are you sure you want to delete the \"" + ((CopyProfile) this.profileCombo.getSelectedItem()).getName() + "\" profile?",
					"Delete Profile?",
					JOptionPane.YES_NO_OPTION,
					JOptionPane.WARNING_MESSAGE,
					null,
					options,
					options[1]
				);
				
				if (decision ==  1) {
					this.profileCombo.removeItem(this.profileCombo.getSelectedItem());
				}

				Persistor.getPersistor().save();
				
				this.isDialogOpen = false;
			}
		}
	}
}

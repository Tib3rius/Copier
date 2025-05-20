package com.whiteoaksecurity.copier.components;
import com.whiteoaksecurity.copier.GlobalCopyProfile;
import com.whiteoaksecurity.copier.listeners.CopyContentMenuListener;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.whiteoaksecurity.copier.CopyProfile;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

public class CopyContextMenu implements ContextMenuItemsProvider {
	
	private MontoyaApi api;
	private GlobalCopyProfile globalProfile;
	private JComboBox<CopyProfile> profiles;
	
	public CopyContextMenu(MontoyaApi api, GlobalCopyProfile globalProfile, JComboBox<CopyProfile> profiles) {
		this.api = api;
		this.globalProfile = globalProfile;
		this.profiles = profiles;
	}

	@Override
	public List<Component> provideMenuItems(ContextMenuEvent event) {
		if (!event.selectedRequestResponses().isEmpty() || !event.messageEditorRequestResponse().isEmpty()) {
			List<Component> list = new ArrayList<>();

			JMenu copyRequestResponse = new JMenu("Copy Request / Response");
			JMenu copyRequest = new JMenu("Copy Request");
			JMenu copyResponse = new JMenu("Copy Response");

			for (int i = 0; i < this.profiles.getItemCount(); i++) {
				int numRequestRules = this.profiles.getItemAt(i).getRequestRulesTableModel().getRowCount();
				int numResponseRules = this.profiles.getItemAt(i).getResponseRulesTableModel().getRowCount();
				
				JMenuItem menuItem;

				if (numRequestRules > 0 || numResponseRules > 0) {
					menuItem = new JMenuItem(this.profiles.getItemAt(i).getName());
					menuItem.addActionListener(new CopyContentMenuListener(this.globalProfile, this.profiles.getItemAt(i), true, true, event));
					copyRequestResponse.add(menuItem);
				}

				if (numRequestRules > 0) {
					menuItem = new JMenuItem(this.profiles.getItemAt(i).getName());
					menuItem.addActionListener(new CopyContentMenuListener(this.globalProfile, this.profiles.getItemAt(i), true, false, event));
					copyRequest.add(menuItem);
				}

				if (numResponseRules > 0) {
					menuItem = new JMenuItem(this.profiles.getItemAt(i).getName());
					menuItem.addActionListener(new CopyContentMenuListener(this.globalProfile, this.profiles.getItemAt(i), false, true, event));
					copyResponse.add(menuItem);
				}
			}

			list.add(copyRequestResponse);
			list.add(copyRequest);
			list.add(copyResponse);

			return list;
		}
		
		return null;
	}
    
}

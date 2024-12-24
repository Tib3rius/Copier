package com.whiteoaksecurity.copier.listeners;

import com.whiteoaksecurity.copier.Persistor;
import com.whiteoaksecurity.copier.Rule;
import com.whiteoaksecurity.copier.models.RulesTableModel;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;

public class AddEditRuleListener extends WindowAdapter implements ActionListener {

	private JFrame parent;
	private JTable table;
	private Rule rule;
	
	public AddEditRuleListener(JFrame parent, JTable table) {
		this.parent = parent;
		this.table = table;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		if (event.getActionCommand().equals("Add") || (event.getActionCommand().equals("Edit") && this.table.getSelectedRowCount() != 0)) {
			RulesTableModel model = (RulesTableModel) table.getModel();

			String title = "";
			String submit = "";

			JLabel enabledLabel = new JLabel("Enabled:");
			JCheckBox enabled = new JCheckBox();
			enabled.setSelected(true);
			JLabel locationLabel = new JLabel("Location:");
			JComboBox locations = new JComboBox(model.getLocations());
			locations.setMaximumSize(locations.getPreferredSize());
			JLabel matchLabel = new JLabel("Match:");
			JTextField matchField = new JTextField(20);
			JLabel replaceLabel = new JLabel("Replace:");
			JTextField replaceField = new JTextField(20);
			JLabel regexLabel = new JLabel("Regex:");
			JCheckBox regex = new JCheckBox();
			regex.setSelected(true);
			JLabel caseSensitiveLabel = new JLabel("Case Sensitive:");
			JCheckBox caseSensitive = new JCheckBox();
			caseSensitive.setSelected(false);
			JLabel commentLabel = new JLabel("Comment:");
			JTextField commentField = new JTextField(20);

			switch (event.getActionCommand()) {
				case "Add" -> {
					title = "Add " + model.getRuleType() + " Rule";
					submit = "Add";
				}
				case "Edit" -> {
					title = "Edit " + model.getRuleType() + " Rule";
					submit = "Edit";
					this.rule = model.getData().get(table.getSelectedRow());
					enabled.setSelected(this.rule.isEnabled());
					locations.setSelectedItem(model.getLocations()[this.rule.getLocation()]);
					matchField.setText(this.rule.getMatch());
					replaceField.setText(this.rule.getReplace());
					regex.setSelected(this.rule.isRegex());
					caseSensitive.setSelected(this.rule.isCaseSensitive());
					commentField.setText(this.rule.getComment());
				}
			}

			JDialog ruleDialog = new JDialog(this.parent, title, true);
			ruleDialog.addWindowListener(this);
			ruleDialog.setResizable(true);
			JPanel rulePanel = new JPanel();
			GroupLayout layout = new GroupLayout(rulePanel);

			JLabel ruleErrorLabel = new JLabel();
			ruleErrorLabel.setForeground(Color.RED);

			JButton submitButton = new JButton(submit);
			submitButton.addActionListener((ActionEvent e) -> {
				if (matchField.getText().length() == 0) {
					ruleErrorLabel.setText("Match cannot be empty.");
					ruleDialog.pack();
				} else if (!checkRegex(matchField.getText(), caseSensitive.isSelected(), regex.isSelected())) {
					ruleErrorLabel.setText("Match regex is invalid.");
					ruleDialog.pack();
				} else {

					switch (event.getActionCommand()) {
						case "Add" -> {
							this.rule = new Rule(
								enabled.isSelected(),
								locations.getSelectedIndex(),
								matchField.getText(),
								replaceField.getText(),
								regex.isSelected(),
								caseSensitive.isSelected(),
								commentField.getText()
							);
							model.add(this.rule);
							Persistor.getPersistor().save();
						}
						case "Edit" -> {
							this.rule.setLocation(locations.getSelectedIndex());
							this.rule.setReplace(replaceField.getText());
							this.rule.setIsRegex(regex.isSelected());
							this.rule.setIsCaseSensitive(caseSensitive.isSelected());
							this.rule.setComment(commentField.getText());

							// Do this last since we need to compile the pattern using potentially new flags.
							this.rule.setMatch(matchField.getText());

							this.rule.setIsEnabled(enabled.isSelected());
							Persistor.getPersistor().save();
						}
					}

					model.fireTableDataChanged();
					table.repaint();

					ruleDialog.dispose();
				}
			});

			JButton cancelButton = new JButton("Cancel");
			cancelButton.addActionListener((ActionEvent e) -> {
				ruleDialog.dispose();
			});


			layout.setAutoCreateGaps(true);
			layout.setAutoCreateContainerGaps(true);
			rulePanel.setLayout(layout);

			layout.setHorizontalGroup(layout.createSequentialGroup()
				.addGap(15)
				.addGroup(layout.createParallelGroup()
					.addComponent(enabledLabel)
					.addComponent(locationLabel)
					.addComponent(matchLabel)
					.addComponent(replaceLabel)
					.addComponent(regexLabel)
					.addComponent(caseSensitiveLabel)
					.addComponent(commentLabel)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(enabled)
					.addComponent(locations)
					.addComponent(matchField)
					.addComponent(replaceField)
					.addComponent(regex)
					.addComponent(caseSensitive)
					.addComponent(commentField)
					.addGroup(layout.createSequentialGroup()
						.addComponent(submitButton)
						.addComponent(cancelButton)
					)
					.addComponent(ruleErrorLabel)
				)
				.addGap(15)
			);

			layout.setVerticalGroup(layout.createSequentialGroup()
				.addGap(15)
				.addGroup(layout.createParallelGroup()
					.addComponent(enabledLabel)
					.addComponent(enabled)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(locationLabel)
					.addComponent(locations)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(matchLabel)
					.addComponent(matchField)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(replaceLabel)
					.addComponent(replaceField)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(regexLabel)
					.addComponent(regex)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(caseSensitiveLabel)
					.addComponent(caseSensitive)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(commentLabel)
					.addComponent(commentField)
				)
				.addGroup(layout.createParallelGroup()
					.addComponent(submitButton)
					.addComponent(cancelButton)
				)
				.addComponent(ruleErrorLabel)
				.addGap(15)
			);

			ruleDialog.getContentPane().add(rulePanel);
			ruleDialog.pack();

			ruleDialog.setMinimumSize(new Dimension(ruleDialog.getPreferredSize().width, ruleDialog.getPreferredSize().height));
			ruleDialog.setLocationRelativeTo(parent);
			ruleDialog.setVisible(true);
		}
	}
	
	public boolean checkRegex(String match, boolean caseSensitive, boolean regex) {
		int flags = 0;
		if (!caseSensitive) {
			flags = flags | Pattern.CASE_INSENSITIVE;
		}
		
		if (regex == Rule.LITERAL) {
			flags = flags | Pattern.LITERAL;
		}
		
		try {
			Pattern.compile(match, flags);
		} catch (PatternSyntaxException e) {
			return false;
		}
		
		return true;
	}
}

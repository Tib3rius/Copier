package com.whiteoaksecurity.copier.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.whiteoaksecurity.copier.GlobalCopyProfile;
import com.whiteoaksecurity.copier.Rule;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

@JsonIgnoreProperties({"ruleType", "locations", "columnCount", "rowCount", "tableModelListeners"})
public class RulesTableModel extends AbstractTableModel {

	String ruleType = "Rule";
	private final String[] columnNames = {"Enabled", "Location", "Match", "Replace", "Type", "Case Sensitive", "Comment"};
	String[] locations;
	private ArrayList<Rule> data = new ArrayList<>();

	public RulesTableModel() {
		this.locations = new String[0];
	}
	
	public String getRuleType() {
		return this.ruleType;
	}
	
	public String[] getLocations() {
		return this.locations;
	}
	
	@Override
	public int getRowCount() {
		return data.size();
	}
	
	public ArrayList<Rule> getData() {
		return data;
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}
	
	@Override
	public String getColumnName(int columnIndex) {
		return columnNames[columnIndex];
	}
	
	@Override
    public Class getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> Boolean.class;
            case 1 -> String.class;
			case 2 -> String.class;
			case 3 -> String.class;
			case 4 -> String.class;
			case 5 -> Boolean.class;
			case 6 -> String.class;
			default -> String.class;
        };
    }

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Rule r = this.data.get(rowIndex);
		
		return switch (columnIndex) {
			case 0 -> r.isEnabled();
			case 1 -> locations[r.getLocation()];
			case 2 -> r.getMatch();
			case 3 -> r.getReplace();
			case 4 -> r.isRegex() ? "Regex" : "Literal";
			case 5 -> r.isCaseSensitive();
			case 6 -> r.getComment();
			default -> "";
		};
	}
	
	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		Rule r = data.get(rowIndex);
		
		switch (columnIndex) {
			case 0 -> r.setIsEnabled((Boolean) value);
		}
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == 0) {
			return true;
		}
		return false;
	}
	
	public void add(Rule r) {
		data.add(r);
	}

	public void clear() {
		data.clear();
		fireTableDataChanged();
	}
}

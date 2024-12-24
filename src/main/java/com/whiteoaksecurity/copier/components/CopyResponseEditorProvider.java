package com.whiteoaksecurity.copier.components;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.whiteoaksecurity.copier.CopyProfile;
import com.whiteoaksecurity.copier.GlobalCopyProfile;

import javax.swing.JComboBox;

public class CopyResponseEditorProvider implements HttpResponseEditorProvider {
	
	private MontoyaApi api;
	private GlobalCopyProfile globalProfile;
	private JComboBox<CopyProfile> profiles;
	
	public CopyResponseEditorProvider(MontoyaApi api, GlobalCopyProfile globalProfile, JComboBox<CopyProfile> profiles) {
		this.api = api;
		this.globalProfile = globalProfile;
		this.profiles = profiles;
	}

	@Override
	public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
		return new CopyResponseEditor(this.api, this.globalProfile, this.profiles, creationContext);
	}

}

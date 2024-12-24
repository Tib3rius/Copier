package com.whiteoaksecurity.copier;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

import javax.swing.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class Persistor {
    private static Persistor INSTANCE;
    private MontoyaApi api;
    private GlobalCopyProfile globalCopyProfile;
    private JComboBox<CopyProfile> profiles;

    public Persistor(MontoyaApi api) {
        this.api = api;
        INSTANCE = this;
    }

    public static Persistor getPersistor() {
        return INSTANCE;
    }

    public void setGlobalCopyProfile(GlobalCopyProfile globalCopyProfile) {
        this.globalCopyProfile = globalCopyProfile;
    }

    public void setCopyProfiles(JComboBox<CopyProfile> profiles) {
        this.profiles = profiles;
    }

//    public void saveGlobalCopyProfile(CopyProfile globalProfile) {
//        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
//        objectMapper.registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES));
//        try {
//            String json = objectMapper.writeValueAsString(globalProfile);
//            this.api.persistence().preferences().setString("GlobalCopyProfile", json);
//        } catch (JsonProcessingException ex) {
//            this.api.logging().logToError(ex.getMessage());
//        }
//    }

    public void save() {
        ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES));

        Map<String, Object> jsonMap = new LinkedHashMap<>();

        jsonMap.put("version", "2");

        jsonMap.put("globalProfile", this.globalCopyProfile);

        CopyProfile[] profileArray = new CopyProfile[this.profiles.getItemCount()];
        for (int i = 0; i < this.profiles.getItemCount(); i++) {
            profileArray[i] = this.profiles.getItemAt(i);
        }
        jsonMap.put("profiles", profileArray);

        try {
            String json = objectMapper.writeValueAsString(jsonMap);
            this.api.persistence().preferences().setString("CopyProfiles", json);
        } catch (JsonProcessingException ex) {
            this.api.logging().logToError(ex.getMessage());
        }
    }
}

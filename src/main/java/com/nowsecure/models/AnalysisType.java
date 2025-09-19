package com.nowsecure.models;

public enum AnalysisType {
    STATIC("static"),
    FULL("full");

    private final String description;

    AnalysisType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return this.description;
    }
}

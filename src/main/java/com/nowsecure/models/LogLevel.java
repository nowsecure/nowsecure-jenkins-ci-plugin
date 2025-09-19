package com.nowsecure.models;

public enum LogLevel {
    DEBUG("debug"),
    INFO("info"),
    WARN("warn"),
    ERROR("error");

    private final String description;

    LogLevel(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

}

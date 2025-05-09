package ru.rtln.common.model;

import java.io.Serializable;

public class ErrorModel implements Serializable {

    private final Integer statusCode;
    private final String exception;
    private final String message;

    public ErrorModel(Integer statusCode, String exception, String message) {
        this.statusCode = statusCode;
        this.exception = exception;
        this.message = message;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getException() {
        return exception;
    }

    public String getMessage() {
        return message;
    }
}
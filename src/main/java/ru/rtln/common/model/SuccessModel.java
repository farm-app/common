package ru.rtln.common.model;

import java.io.Serializable;

public class SuccessModel<T> implements Serializable {

    private Integer statusCode;
    private String subject;
    private T data;

    public SuccessModel() {
    }

    public SuccessModel(Integer statusCode, String subject, T data) {
        this.statusCode = statusCode;
        this.subject = subject;
        this.data = data;
    }

    public static <T> SuccessModel<T> okSuccessModel(T data, String subject) {
        return new SuccessModel<>(200, subject, data);
    }

    public static SuccessModel<String> deletedSuccessModel(String subject) {
        return new SuccessModel<>(200, subject, "Successfully deleted");
    }

    public static <T> SuccessModel<T> createdSuccessModel(T data, String subject) {
        return new SuccessModel<>(201, subject, data);
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getSubject() {
        return subject;
    }

    public T getData() {
        return data;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setData(T data) {
        this.data = data;
    }
}

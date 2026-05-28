package com.solo.solo_one.common;

import lombok.Getter;

@Getter
public enum ResEnum {
    SUCCESS(0, "SUCCESS"),
    ERROR(1, "ERROR"),
    NEED_LOGIN(10, "NEED_LOGIN"),
    ILLEGAL_ARGUMENT(2, "ILLEGAL_ARGUMENT");

    private final int code;
    private final String desc;

    ResEnum(int code, String desc) {
        this.code = code;
        this.desc = desc;
    }
}

package com.solo.solo_one.common;

import static com.solo.solo_one.common.ResEnum.ERROR;
import static com.solo.solo_one.common.ResEnum.SUCCESS;

public class BaseResponse {
    public Integer code;
    public String message;
    public Object data;

    public <T> BaseResponse(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public BaseResponse(Integer code, String message) {
        this.code = code;
        this.message = message;
        this.data = null;
    }

    public <T> BaseResponse(ResEnum r, T data) {
        this.code = r.getCode();
        this.message = r.getDesc();
        this.data = data;
    }

    public <T> BaseResponse success(T data) {
        return new BaseResponse(SUCCESS.getCode(), SUCCESS.getDesc(), data);
    }

    public BaseResponse success() {
        return new BaseResponse(SUCCESS.getCode(), SUCCESS.getDesc());
    }

    public BaseResponse error() {
        return new BaseResponse(ERROR.getCode(), ERROR.getDesc());
    }
}

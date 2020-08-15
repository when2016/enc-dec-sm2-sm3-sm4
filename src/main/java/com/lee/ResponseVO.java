package com.lee;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseVO<T> {

    public enum Code{
        SUCCESS("e0000", "ok"),
        FAIL("e0001", "fail");

        String code;
        String msg;

        Code(String code, String msg){
            this.code = code;
            this.msg = msg;
        }
    }

    private String errCode;
    private String errMessage;
    private T body;

    public ResponseVO(Code code, T data){
        this.errCode = code.code;
        this.errMessage = code.msg;
        this.body = data;
    }

    public static <T> ResponseVO<T> success(T data){
        return new ResponseVO<>(Code.SUCCESS, data);
    }

    public static <T> ResponseVO<T> fail(T data){
        return new ResponseVO<>(Code.FAIL, data);
    }

}

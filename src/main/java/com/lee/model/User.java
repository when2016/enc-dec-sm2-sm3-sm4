package com.lee.model;

import lombok.Builder;
import lombok.Data;

/**
 * @Auther: liyiyu
 * @Date: 2020/6/27 23:28
 * @Description:
 */
@Builder
@Data
public class User {

    private String name;
    private Integer sex;
    private Integer age;


}

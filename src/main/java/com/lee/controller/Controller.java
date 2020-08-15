package com.lee.controller;

import com.lee.ResponseVO;
import com.lee.dto.LoginDTO;
import com.lee.model.User;
import com.lee.annotation.Decrypt;
import com.lee.annotation.Encrypt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;



/**
 * @Auther: liyiyu
 * @Date: 2020/6/27 18:26
 * @Description:
 */
@RestController
public class Controller {

    @Decrypt
    @Encrypt
    @PostMapping("/login")
    public ResponseVO<User> login(LoginDTO loginDTO){
        if ("lee".equals(loginDTO.getUsername()) && "123".equals(loginDTO.getPassword())){
            User user = User.builder()
                    .name("lee")
                    .sex(1)
                    .age(18)
                    .build();

            return ResponseVO.success(user);
        }else {
            User user = User.builder().build();
            return ResponseVO.fail(user);
        }

    }



}

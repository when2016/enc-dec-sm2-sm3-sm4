package com.lee.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Auther: liyiyu
 * @Date: 2020/6/27 22:21
 * @Description:
 */
@Slf4j
@Controller
@RequestMapping("/")
@Configuration
class IndexController {


    /**
     * 跳转首页
     */
    @GetMapping("")
    public void index1(HttpServletResponse response) {
        //内部重定向
        try {
            response.sendRedirect("/index");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @GetMapping("index")
    public ModelAndView index() {
        ModelAndView modelAndView = new ModelAndView("index");
        return modelAndView;
    }

}
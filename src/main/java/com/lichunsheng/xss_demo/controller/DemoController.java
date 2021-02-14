package com.lichunsheng.xss_demo.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/demo")
@CrossOrigin
public class DemoController {
    @GetMapping("/xssTest")
    public String xssTest(String parameter) {
        System.out.println(parameter + "进入");
        return "操作成功";
    }

    /*
     * 过滤json
     * */
    @PostMapping("/json")
    public String json(@RequestBody String json) {
        System.out.println(json);
        return json;
    }
}

package com.lichunsheng.xss_demo.config;

import com.lichunsheng.xss_demo.filter.XssFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean myFilter() {
        FilterRegistrationBean myFilter = new FilterRegistrationBean();
        myFilter.addUrlPatterns("/*");
        myFilter.setOrder(1);
        myFilter.setFilter(new XssFilter());
        return myFilter;
    }
}

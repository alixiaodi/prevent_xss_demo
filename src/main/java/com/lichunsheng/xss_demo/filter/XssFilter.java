package com.lichunsheng.xss_demo.filter;

import com.lichunsheng.xss_demo.wrapper.XssRequestWrapper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;


public class XssFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        /* filterChain.doFilter(new XssHttpServletRequestWrapper2(request),servletResponse);*/
        filterChain.doFilter(new XssRequestWrapper(request), servletResponse); //包装request，在里头进行XSS清洗
    }
}

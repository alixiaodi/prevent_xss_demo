package com.lichunsheng.xss_demo.wrapper;

import com.alibaba.fastjson.JSON;
import org.owasp.validator.html.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.util.Iterator;
import java.util.Map;

public class XssRequestWrapper extends HttpServletRequestWrapper {
    private static Policy policy = null;

    static {
        //初始化策略
        /**
         * antisamy-anythinggoes.xml    非常危险，允许HTML、CSS、Javascript通过
         * antisamy-ebay.xml    相对安全，对内容进行过滤。适用于电子商务网站，允许用户输入HTML脚本作为页面的一部分
         * antisamy-myspace.xml 相对危险，适用于社交网站，允许用户输入作为整个页面
         * antisamy-slashdot.xml    适用于新闻网站的评论过滤
         * antisamy-tinymce.xml 相对安全，只允许文本格式通过
         */
        InputStream resourceAsStream = XssRequestWrapper.class.getClassLoader().getResourceAsStream("antisamy-ebay.xml");
        try {
            policy = Policy.getInstance(resourceAsStream);
        } catch (PolicyException e) {
            e.printStackTrace();
        }
    }

    public XssRequestWrapper(HttpServletRequest request) {
        super(request);
    }


    /**
     * @desc Header为空直接返回，不然进行XSS清洗
     * @author howinfun
     * @date 2018/10/24
     */
    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        if (StringUtils.isEmpty(value)) {
            return value;
        } else {
            String newValue = cleanXSS(value);
            return newValue;
        }

    }

    /**
     * @desc Parameter为空直接返回，不然进行XSS清洗
     * @author howinfun
     * @date 2018/10/24
     */
    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        if (StringUtils.isEmpty(value)) {
            return value;
        } else {
            value = cleanXSS(value);
            return value;
        }
    }

    /**
     * @desc 对用户输入的参数值进行XSS清洗
     * @author howinfun
     * @date 2018/10/24
     */
    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values != null) {
            int length = values.length;
            String[] escapseValues = new String[length];
            for (int i = 0; i < length; i++) {
                escapseValues[i] = cleanXSS(values[i]);
            }
            return escapseValues;
        }
        return super.getParameterValues(name);
    }

    /*
     * 清洗json数据
     * */
    @Override
    public ServletInputStream getInputStream() throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(super.getInputStream(), "UTF-8"));
        StringBuilder stringBuilder = new StringBuilder();
        String string;
        while ((string = bufferedReader.readLine()) != null) {
            stringBuilder.append(string);
        }
//        将json转换为map
        Map<String, Object> map = JSON.parseObject(stringBuilder.toString(), Map.class);
        map.keySet().forEach(s -> {
            map.put(s, cleanXSS(map.get(s).toString()));
        });
//        将map转换为json
        String json = JSON.toJSONString(map);
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(json.getBytes());
        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener readListener) {

            }
        };
    }

    /**
     * @desc AntiSamy清洗数据
     * @author howinfun
     * @date 2018/10/24
     */
    private String cleanXSS(String taintedHTML) {
        try {
            AntiSamy antiSamy = new AntiSamy();
            CleanResults cr = antiSamy.scan(taintedHTML, policy);
            taintedHTML = cr.getCleanHTML();
            return taintedHTML;

        } catch (ScanException e) {
            e.printStackTrace();
        } catch (PolicyException e) {
            e.printStackTrace();
        }
        return taintedHTML;
    }

}
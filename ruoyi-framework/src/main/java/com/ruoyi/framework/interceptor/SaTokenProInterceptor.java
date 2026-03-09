package com.ruoyi.framework.interceptor;

import cn.dev33.satoken.stp.StpUtil;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * Pro版Token校验拦截器（无setConfig，直接用StpUtil）
 */
public class SaTokenProInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Pro版核心校验API（自动读取配置Bean，无需手动setConfig）
        StpUtil.checkLogin();
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        if (ex != null) {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter writer = response.getWriter();
            writer.write("{\"code\":401,\"msg\":\"Token无效或已过期\",\"data\":null}");
            writer.close();
        }
    }
}
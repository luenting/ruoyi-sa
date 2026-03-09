package com.ruoyi.framework.config;

import cn.dev33.satoken.config.SaTokenConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Sa-Token Pro版最终配置（无setConfig，适配Pro版API，复用若依Redis）
 */
@Configuration
public class SaTokenProConfig {

    /**
     * 配置Sa-Token核心参数（Pro版中，该Bean会自动生效，无需StpUtil.setConfig）
     */
    @Bean
    public SaTokenConfig saTokenConfig() {
        SaTokenConfig config = new SaTokenConfig();
        // 1. Token基础配置（和若依对齐）
        config.setTokenName("Authorization"); // 沿用若依的Token参数名
        config.setTimeout(7200);              // Token有效期2小时（秒）
        config.setActiveTimeout(-1);        // 30分钟自动续期（Pro版特性）
        config.setIsConcurrent(true);         // 允许多端登录
//        config.setTokenPrefix("sys_login:");  // 对齐若依的Redis Key前缀
        return config;
    }
}
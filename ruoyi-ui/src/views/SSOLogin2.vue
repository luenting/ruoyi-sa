<template>
  <div class="sso-login-container">
    123
  </div>
</template>

<script>
import { ssoLogin } from "@/api/login";
import { setToken } from "@/utils/auth";
// 若使用Cookie存储Token，需安装并导入js-cookie（可选）
// import Cookies from 'js-cookie'

export default {
  name: "SSOLogin",
  data() {
    return {
      loading: true, // 加载状态
      errorMsg: "", // 错误信息
    };
  },
  mounted() {
    // 页面挂载后自动执行Ticket验证逻辑
    this.doLoginByTicket();
  },
  created() {
    console.log("开始SSO登录，URL参数：", window.location.search);
  },
  methods: {
    /**
     * 从URL中提取Ticket参数
     */
    getTicketFromUrl() {
      const urlParams = new URLSearchParams(window.location.search);
      return urlParams.get("ticket") || "";
    },

    /**
     * 核心逻辑：通过Ticket获取Token并完成登录
     */
    async doLoginByTicket() {
        console.log("开始SSO登录，URL参数：", window.location.search);
      try {
        const ssoLoginResult = await ssoLogin(getTicketFromUrl());
        console.log("SSO登录结果：", ssoLoginResult);
        if (ssoLoginResult.code === 200) {
          setToken(ssoLoginResult.data.token);
        } else {
          throw new Error(ssoLoginResult.message || "登录失败，请重试");
        }
      } catch (err) {
        // 捕获异常并展示错误
        this.errorMsg = err.message || "登录异常，请联系管理员";
        console.error("SSO登录失败：", err);
      } finally {
        // 结束加载状态
        this.loading = false;
      }
    },
  },
};
</script>

<style scoped>
.sso-login-container {
  width: 100vw;
  height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: #f5f7fa;
}

.loading {
  text-align: center;
  color: #666;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid #eee;
  border-top: 4px solid #409eff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

.error {
  text-align: center;
  color: #f56c6c;
  padding: 20px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

.retry-btn {
  margin-top: 16px;
  padding: 8px 16px;
  background: #409eff;
  color: #fff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.retry-btn:hover {
  background: #66b1ff;
}

.empty {
  width: 100%;
  height: 100%;
}
</style>

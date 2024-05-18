package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 静态资源不用拦截 ==> 为了提高性能，静态资源一般不涉及安全问题
        web.ignoring().antMatchers("/resources/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 认证——登录时拦截

        // AuthenticationManager - 认证核心接口
        // AuthenticationManagerBuilder - 用于构建AuthenticationManager对象的工具
        // ProviderManager - AuthenticationManager默认实现类

        // 内置的认证规则
        // "12345"是salt，但是不符合我们原来项目的内容，因为这里的salt是固定的，而我们的项目salt是根据用户改变的
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));

        // 自定义认证规则
        // ProviderManager持有一组AuthenticationProvider，每一个AuthenticationProvider负责一种认证，ProviderManager本身不做认证
        // 符合设计模式之委托模式：每个Provider负责一种登录（账号密码，oauth2，刷脸等）
        // 我们目前只有账号密码登录
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication：用于封装认证信息（账号密码）的接口，不同的实现类代表不同的认证信息
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                // 写认证逻辑，这里是账号密码的判断
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);
                if(user == null){
                    throw new UsernameNotFoundException("账号不存在！");
                }
                password = CommunityUtil.md5(password + user.getSalt());
                if(!user.getPassword().equals(password)){
                    throw new BadCredentialsException("密码不正确！");
                }

                // 返回类中要携带参数：认证主体（一般为user），证书（密码）或能代替证书的东西，权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            @Override
            public boolean supports(Class<?> aClass) {
                // 当前接口支持的是什么认证类型

                // UsernamePasswordAuthenticationToken是Authentication的常用实现类，代表账号密码认证
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
                // 当前认证类型是账号密码登录认证模式
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 授权

        // 登录配置
        // 我的登录页面（替换security自带登录页）
        http.formLogin()
                .loginPage("/loginpage")  // 登录页面
                .loginProcessingUrl("/login")  // 处理登录请求的路径
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");  // 跳转至首页
                    }
                })   // 登录成功时处理逻辑
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        // 回到登录页面不能重定向，因为重定向后请求变了，不方便后续传参（只能用跨请求组件cookie or session）
                        // 我们这里使用转发（迫不得已，因为不是controller无法返回模板），转发时还是一个请求
                        request.setAttribute("error", e.getMessage());
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                    }
                })  //登录失败时处理逻辑
        ;

        // 登出相关配置
        http.logout().logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                })
        ;

        // 授权相关配置
        // 权限与路径的映射
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied") // 权限不匹配跳转
        ;

        // 增加filter，用于验证码
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                // ServletRequest是HttpServletRequest的父接口，我们通常用HttpServletRequest，因为方法更多
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;

                // 仅登录请求处理验证码
                if(request.getServletPath().equals("/login")){
                    String verifyCode = request.getParameter("verifyCode");
                    if(verifyCode == null || !verifyCode.equalsIgnoreCase("1234")){
                        // 验证码不对
                        request.setAttribute("error", "验证码错误！");
                        // 由于有错误传参，因此转发
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }
                filterChain.doFilter(request, response);  // 请求通过了拦截，继续向下走
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl()) //计入内存里
                .tokenValiditySeconds(3600 * 24)  // 24h
                .userDetailsService(userService);  // 利用内存中的数据和userService作查询与处理

    }
}

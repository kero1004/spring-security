package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@EnableWebSecurity  // 웹 보안 활성화 시키기 위함
@Configuration  //설정 클래스
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //인가 정책 - 어떤 요청에 대해 인증 받도록 설정
        http.authorizeRequests()
                .anyRequest().authenticated();

        //인증 정책 - formLogin 설정
        http.formLogin()
        .loginPage("/loginPage")                              // 사용자 정의 로그인 페이지
        .defaultSuccessUrl("/")                                 // 인증 성공시 이동할 수 있는 url
                        .failureUrl("/login")                   // 인증 실패시 이동하는 url
                        .usernameParameter("userId")            // username의 name명 - default는 username
                        .passwordParameter("passwd")            // password의 name명 - default는 password
                        .loginProcessingUrl("/login_proc")      // form태그의 action url설정 - default는 /login
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                                // authentication : 인증에 성공했을때 인증한 결과를 담은 인증 객체

                                System.out.println("authentication " + authentication.getName());
                httpServletResponse.sendRedirect("/");  // 루트 페이지로 이동
            }
        })   //로그인 성공 핸들러 - 우리는 익명클래스 사용
        .failureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                System.out.println("exception " + e.getMessage());
                httpServletResponse.sendRedirect("/login");
            }
        })  // 실패 핸들러
        .permitAll();   // 누구나 접근 가능하도록 해야한다. ( permitAll 을 하지않으면 젤 위에 인가정책때문에 /loginPage 에 접근이 불가능하다.
    }
}

package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@EnableWebSecurity  // 웹 보안 활성화 시키기 위함
@Configuration  //설정 클래스
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;  //use to remember-me

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {  //사용자 생성, 권한 설정
        //메모리 방식으로 사용자 생성 - 갯수 제한 없음
        //{noop} 패스워드 암호화 알고리즘 방식을 prefix형태로 작성해줘야함 {noop}은 평문으로 암호화
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");  //("ADMIN", "SYS", "USER")가능
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //인가 정책 - 어떤 요청에 대해 인증 받도록 설정
//        http.authorizeRequests()
//                .anyRequest().authenticated();

        //인증 정책 - formLogin 설정
        http
                .formLogin()
                //.loginPage("/loginPage")              // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                 // 인증 성공시 이동할 수 있는 url
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

        //로그아웃
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")
                .and()
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600) //14일
                .userDetailsService(userDetailsService)
        ;

//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);

        //세션 고정 방지
        http
                .sessionManagement()
                .sessionFixation().changeSessionId();

        //인가 정책 - 권한 설정
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

    }
}

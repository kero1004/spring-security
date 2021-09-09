# Spring Security

### 인증 API - Form Login 인증

- http.formLogin() : **Form 로그인 인증 기능**이 작동함

```java
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
            .loginPage("");
            .defaultSuccessUrl("")
            .failureUrl("")
            .usernameParameter("")
            .passwordParameter("")
            .loginProcessingUrl("")
            .successHandler(loginSuccessHandler())
            .failureHandler(loginFailureHandler());
}
```

| method             | desc                                          | default 값 |
| ------------------ | --------------------------------------------- | ---------- |
| loginPage          | 사용자 정의 로그인 페이지                     |
| defaultSuccessUrl  | 로그인 성공 후 이동할 페이지 url              |
| failureUrl         | 로그인 실패시 이동할 페이지 url               |
| usernameParameter  | 아이디 파라미터명 설정(form태그에서 name명)   | username   |
| passwordParameter  | 패스워드 파라미터명 설정(form태그에서 name명) | password   |
| loginProcessingUrl | 로그인 Form Action                            | login      |
| successHandler     | 로그인 성공 후 핸들러                         |
| failureHandler     | 로그인 실패 후 핸들러                         |

// Fixture: intentionally insecure Spring Security config.
package com.example.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()                              // SEC-05
            .authorizeRequests()
            .antMatchers("/admin/**").permitAll()          // SEC-06
            .anyRequest().authenticated();
    }
}

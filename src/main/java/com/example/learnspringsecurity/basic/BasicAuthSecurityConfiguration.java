package com.example.learnspringsecurity.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;


@Configuration
public class BasicAuthSecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
      return http
                .authorizeHttpRequests(
                        auth -> {
                            auth.anyRequest().authenticated();
                        }
                )
                .sessionManagement(
                        session -> {
                            session.sessionCreationPolicy(
                                    SessionCreationPolicy.STATELESS
                            );
                        }
                )
                .httpBasic(Customizer.withDefaults())
                .csrf(
                          csrf -> csrf.disable()
                )
                .headers(
                      headers -> headers.frameOptions(
                              frameOptions -> frameOptions.sameOrigin()
                      )
                ) //frame is disable by default so we need to enable it to use h2 database
                .build();
    }

    @Bean
    public DataSource dataSource(){ //configure a h2 database to create table
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
    @Bean
    UserDetailsService userDetailsService(DataSource dataSource){
        var user = User.withUsername("user")
//                .password("{noop}123")  plaintext password
                .password("123")
                .passwordEncoder(str -> bCryptPasswordEncoder().encode(str)) // use BCrypt to hasing password
                .roles("USER")
                .build();
        var admin = User.withUsername("admin")
//                .password("{noop}123")
                .password("123")
                .passwordEncoder(str -> bCryptPasswordEncoder().encode(str))
                .roles("ADMIN","USER")
                .build();
       var jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);
       jdbcUserDetailsManager.createUser(user);
       jdbcUserDetailsManager.createUser(admin);
       return jdbcUserDetailsManager;
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


//    @Bean
//    UserDetailsService userDetailsService(){
//        var user = User.withUsername("user")
//                .password("{noop}123")
//                .roles("USER")
//                .build();
//        var admin = User.withUsername("admin")
//                .password("{noop}123")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user, admin);
//    }
}

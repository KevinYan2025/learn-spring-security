package com.example.learnspringsecurity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;



import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


//@Configuration
public class JwtAuthSecurityConfiguration {

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
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    public DataSource dataSource() { //configure a h2 database to create table
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(DataSource dataSource) {
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
                .roles("ADMIN", "USER")
                .build();
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public KeyPair keyPair(){
        //create key pair use KeyPairGenerator
        try{
            var keyPairGenerator =KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); //init the size of key
            return keyPairGenerator.generateKeyPair();
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }
    @Bean
    public RSAKey rsaKey(KeyPair keyPair){
        //create RSAKey using keypair
       return new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){
        //create jwkSet with rsakey
        var jwkSet = new JWKSet(rsaKey);
        //create jwksource with jwkset
        return ((jwkSelector, context) -> jwkSelector.select(jwkSet));
    }
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        //create jwtdecoder with rsa public key
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        //create jwtencoder with jwksource
        return new NimbusJwtEncoder(jwkSource);
    }


}

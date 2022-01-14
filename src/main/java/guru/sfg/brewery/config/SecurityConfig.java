package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
                    http
                        .authorizeRequests(authorize -> {
                            authorize
                                    .antMatchers("/h2-console/**").permitAll() // do not use in production!
                                    .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                                    .antMatchers("/beers/find", "/beers*").permitAll()
                                    .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                                    .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                                    .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                        } )
                        .authorizeRequests()
                        .anyRequest().authenticated()
                        .and()
                        .formLogin().and()
                        .httpBasic()
                        .and().csrf().disable();
                    //h2 console config
                    http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

/*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$p55/OxlZFzdoyqAjjt4Se.IN.T2m/pfVnCyFQHp6cNCVLuvzZL6Nq")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}a318bd2b5ac2b904e2f20ed6f0f87216294aff7d0ee1ca78b23d884a846c136a86ec439788302b41")
                .roles("USER");

        auth.inMemoryAuthentication().withUser("scott").password("{bcrypt10}$2a$10$FZw5UYNPq5KUJFlmOSkKGeL.SmN7Eyjslk133wtpfh4ypDsRbreLS").roles("CUSTOMER");
    }
*/

    //    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }















}

package com.srda.demoSecurityJwt.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//12.0 Va dire à Spring comment lier la sécurité.
@Configuration
//Config et enable doivent être ensemble lorsqu'on travaill avec boot 3.0
@EnableWebSecurity
// IL va regarder si y'a bien un sécurity filter chain.
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthentificationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    //  12.1 On créer la méthode.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http
                .csrf() //Disable de csrf verification (pas de précision dans la vidéo)
                .disable()
                //Dans tt les applications on a une "White liste": endpoint sans authentification ou token.
                .authorizeHttpRequests()
                //Pour les requêtes qui correspondent à ce que je défini ici
                //15.0 Je met l'adresse des requêtes qui sont autorisées suivi d'étoiles
                .requestMatchers("/api/v1/auth/**")
                //Je lui dis que c'est permi pour tous.
                .permitAll()
                //Ici je dis, pour les autres requetes
                .anyRequest()
                //Faut être authentifié.
                .authenticated()
                .and()
                    .sessionManagement()
                    //avec ça spring créera une souvelle session pour chaque requete
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //Variable authenticationProvider à créer plus tard.
                .authenticationProvider(authenticationProvider)
                //Je dis before car je veux que le filtre soit exécuté avant le filtre du username et mdp car on check d'abord tout
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

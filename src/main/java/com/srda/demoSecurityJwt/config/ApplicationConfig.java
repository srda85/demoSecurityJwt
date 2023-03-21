package com.srda.demoSecurityJwt.config;

import com.srda.demoSecurityJwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


//11.0 On créer une classe application Config qui contient entre autres les beans.
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;


//  Va indiquer que cette méthode représente un bean. Il doit tjr être public.
    @Bean
    public UserDetailsService userDetailsService(){
        //L'ide va me proposer d'implémenter la méthode automatiquement.
        //SI je reste avec la souris sur le UserDetailService il me propose de le convertir en Lambda.
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

//    12.0 Création d'un authentification provider.
    //C'est l'objet d'accès des données qui est responsable de récupèrer les userdetails et password
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider=new DaoAuthenticationProvider();
        //On doit spécifier quelques propriétés.
        //on lui dit quel service utiliser pour chercher les infos
        authProvider.setUserDetailsService(userDetailsService());
        //Password encoder doit être créer après
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
//    13.0 JE créé un gestionnaire d'identifications
    @Bean
    public AuthenticationManager authenticationManager  (AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}

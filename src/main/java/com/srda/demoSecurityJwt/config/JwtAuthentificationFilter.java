package com.srda.demoSecurityJwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//3.0 Je créé le filtre d'authentification. On veut qu'il soit actif chaque fois qu'une requête est lancée
//3.1 Je dois hériter d'une classe qui permet de filtrer une fois par requête.
@Component // C'est un bean
@RequiredArgsConstructor //3.3 Il va utiliser un constructeur avec tous les attributs final qu'on ajoute.
public class JwtAuthentificationFilter extends OncePerRequestFilter {

//        5.2 J'anticipe la création d'un service jwt. Il permettra par exmple d'extraire le token
//    5.4 Pour créer la classe je cloque simplement sur l'ampoule rouge à coté.
    private final JwtService jwtService;

//    10.1 J'ajoute un userDetailService qui vient de springSecurity. Faudra créer une classe qui implémente cette interface.
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
//            3.2.0 C'est notre requête. On peut en extraire les données et fournir de nouvelles données en réponse.
//            3.2.3 J'ajoute l'annotation NonNull de SpringFrameword.lang pour enlever l'avertissement de l'ide.
            @NonNull HttpServletRequest request,
//            3.2.1 C'est notre réponse
            @NonNull HttpServletResponse response,
//            3.2.2 Cette "chain" est faite selon le design pattern "chain of responsibility" et contient la liste des autres filtres dont on a besoin.
            @NonNull FilterChain filterChain
    )
            throws ServletException, IOException {
//        4.0 Je vérifie si l'utilisateur a bien un Token qu'on passe ds le Header de la requête. Avec ce string on extrait le header, d'où le nom.
//        4.1 Le nom du headers qu'on souhaite est Authorization. Il contient le token JWT.
        final String authHeader=request.getHeader("Authorization");
//        4.2 Je crée un String qui sera le token
        final String jwt;
//        5.0 Je vais devoir récupèrer le nom d'utilisateur pour vérifier s'il est bien dans la BDD. Je commence par créer ce String
        final String userEmail;
//        4.3 Je crée une vérification, si le header n'est pas vide et s'il commence bien par Bearer (tjr pr les tolen JWt).
        if (authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }
//        4.4 Après la vérification, j'assigne le token en commencçant par la 7ème lettre car on ne reprend pas la partie "Bearer"
        jwt = authHeader.substring(7);

//      5.1 J'ai besoin d'une classe qui peut manipuler le token pour en extraire le nom d'utilisateur
//      5.3 J'ajoute la méthode du jwt service qui permet d'extraire le nom en prenant le jwt comme paramètre.
        userEmail= jwtService.extractUserName(jwt);

//      10.0 J'ajoute une méthode qui vérifie bien que l'eamil soit pas nul et pas encore authentifié (dans ce cas là pas besoin de continuer les méthodes).
//      Pour cela j'utilise le securityContextHolder et s'il est null, c'est que l'utilisateur n'est pas authentifié encore.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication()==null){
            //Je vérifie que le user est bien dans la database.
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //11.1 Si le token est valid on doit mettre à jour le securityContext.
            if (jwtService.isTokenValid(jwt,userDetails)){
                // Objet nécessaire à la mise à jour du sécurity context.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        //On a pas de credentials donc passe un null.
                        null,
                        userDetails.getAuthorities()
                );
                //11.2 On veut ajouter quelques détails à partir de notre requête.
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //11.3 On met à jour le context de sécurité.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        //11.4 Pas oublier ceci pour terminer.
        filterChain.doFilter(request,response);

    }
}

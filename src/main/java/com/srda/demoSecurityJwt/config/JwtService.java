package com.srda.demoSecurityJwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

//    6.5 Je créer une variable qui sera la clé de décryptage que je vais chercher sur un site. https://www.allkeysgenerator.com/
//    Minimum requi pour JWT est une clé 256 bits et faut cocher sur HEX!!

    private static final String SECRET_KEY = "6150645367566B59703373367639792442264529482B4D6251655468576D5A71";


//    6.0 Méthode qui extraira le nom d'utilisateur du token.
//    6.1 Il a rajouté les librairies sur le token.
/*    6.2  LE token se divise en trois parties :
        A. Header:
            A.1 Le type du token : ex JWT
            A.2 L'algorithme utilisé.
        B. Payload
            B.1 Claims = données aditionnelles.
            B.2 Il y'a trois type de claims : registered (pas oblig), public et private (custom claims).
        C. Signature. Permet des controles
 */

// 7.1 Je peux enfin terminer la méthode ExtractUsername. On peut à partir de claims extraire bcp de choses différents. (changer getSubject)
    public String extractUserName(String token) {
        return extractClaims(token, Claims::getSubject);
    }

//    7.0 Méthode qui permet d'extraire un unique claims à partir de la méthode AllClaims.
    public <T> T extractClaims(String token, Function<Claims, T>claimsTResolver){
        final Claims claims=extractAllClaims(token);
        return claimsTResolver.apply(claims);
    }


//    6.3 Méthode qui va permettre l'extraction des claims.
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                //Faut utilisser la clé pour créer ou décoder un token.
                //6.4 Rajoute la méthode plus tard.
                .setSigningKey(getSignIngKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

//    6.6 je génère la méthode qui renvoie une clé
    private Key getSignIngKey() {
        //La clé sera décodé ici
        byte[]keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

//    8.0 Je crée uné méthode qui génère les tokens. Elle prend un map en paramètre qui contiendra tous les claims qu'on veut ajouter.
    public String generateToken(
            Map<String,Object>extraClaims,
            UserDetails userDetails)
    {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                // Va ns aider à calculer l'expiration.
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //Ici il sera valide 24 heure et milles secondes.
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                // Je dis avec quelle clé et l'algorithme
                .signWith(getSignIngKey(), SignatureAlgorithm.HS256)
                //Compact va générer et retourner le token
                .compact();
    } //Arrivé ici à 1h08 56

//    8.1 Si je veux créer un token sans extraClaims - Je génère simplement une nouvelle HMap comme paramètre.
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

//    9.0 méthode qui va ns permettre de valider un token
//    On prend les userDetails en paramètre car on veut vérifier si ce token appartient à ce userdétails.
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username=extractUserName(token);
        //Je retourne true si le token n'est pas expiré et que le nom d'utilisateur correspond.
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(token);
    }

//  9.1 méthode de vérification de l'expiration du token
    private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new  Date());
    }

//  9.2 méthode qui va extraire la date du token.
    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

}

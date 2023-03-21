package com.srda.demoSecurityJwt.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

//2.0 Je créé le repository
public interface UserRepository extends JpaRepository <User, Integer> {

//    2.1 J'ajoute une méthode qui permet de récupèrer l'utilisateur par l'email.
    Optional<User>findByEmail(String email);
}

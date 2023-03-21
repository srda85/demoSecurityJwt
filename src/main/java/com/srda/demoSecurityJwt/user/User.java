package com.srda.demoSecurityJwt.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
//Il utilise un undercore devant pour ne pas qu'il y'ait confusion avec le user par défaut de postgres
@Table(name = "_user")
//1.0 Il faut implémenter Spring User details qui est une interface qui contient plusieurs méthodes.
//1.1 J'aurais pu créer par ex: AppUser et faire l'héritage de User qui est une classe déjà définie mais il est préférable pour le controle d'implémenter l'interface.
public class User implements UserDetails {

    @Id
//    Je peux ne rien mettre car la valeur par défaut est auto
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
//    1.10 Si je change le nom de password je vais devoir redéfinir la méthode getPassword du userdetails
    private String password;

//   1.2 Je dois créer un attribut de type Role qui est un enum qui va permettre de déterminer le role.
    @Enumerated(EnumType.STRING)
//    1.3 Vient dire à spring que c'est un enum. Faut préciser le type si on veut autre que Ordinal.
    private Role role;


    @Override
//    1.4 J'édite pour que cela renvoit une liste de new grantedAuthority
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }


    @Override
//    1.5 J'édite pour qu'il renvoie l'email.
    public String getUsername() {
        return email;
    }

    @Override
//    1.6 Je change en true sinon il est expiré.
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
//    1.7 Idem 1.6
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
//    1.8 idem 1.6
    public boolean isCredentialsNonExpired() {
        return true;
    }
// 1.9 Idem 1.6
    @Override
    public boolean isEnabled() {
        return true;
    }
}

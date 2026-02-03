package uce.edu.web.api.auth.application;

import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import uce.edu.web.api.auth.domain.Usuario;
import uce.edu.web.api.auth.infraestructure.UsuarioRepository;

@ApplicationScoped
public class AuthService {

    @Inject
    UsuarioRepository usuarioRepository;

    public Optional<Usuario> validarUsuario(String nombre, String password) {
       Usuario u = usuarioRepository.find("nombre", nombre).firstResult();
       if(u == null){
        return Optional.empty();
       }

       if(!u.getPassword().equals(password)){
        return Optional.empty();
       }
        return Optional.of(u);
    }

}

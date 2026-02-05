package uce.edu.web.api.auth.interfaces;

import java.time.Instant;
import java.util.Set;
import io.smallrye.jwt.build.Jwt;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import uce.edu.web.api.auth.application.AuthService;
import uce.edu.web.api.auth.domain.Usuario;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    AuthService authService;

    @ConfigProperty(name = "auth.issuer")
    String issuer;

    @ConfigProperty(name = "auth.token.ttl")
    long ttl;

    @GET
    @Path("/token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(

            @QueryParam("user") String user,
            @QueryParam("password") String password) {

        // Validación básica de parámetros
        if (user == null || password == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("Faltan parámetros user/password"))
                    .build();
        }

        return authService.validarUsuario(user, password)
                .map(usuario -> generarTokenSiEsAdmin(usuario))
                .orElse(Response.status(Response.Status.UNAUTHORIZED)
                        .entity(new ErrorResponse("Usuario o password incorrectos"))
                        .build());
    }

    private Response generarTokenSiEsAdmin(Usuario usuario) {
        if (!"admin".equalsIgnoreCase(usuario.getRole())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(new ErrorResponse("No autorizado: requiere role admin"))
                    .build();
        }

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttl);

        String jwt = Jwt.issuer(issuer)
                .subject(usuario.getNombre())
                .groups(Set.of(usuario.getRole())) // importante: groups = role
                .issuedAt(now)
                .expiresAt(exp)
                .sign();

        return Response.ok(new TokenResponse(jwt, exp.getEpochSecond(), usuario.getRole())).build();
    }

    public static class TokenResponse {
        public String accessToken;
        public long expiresAt;
        public String role;

        public TokenResponse() {
        }

        public TokenResponse(String accessToken, long expiresAt, String role) {
            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
            this.role = role;
        }
    }

    public static class ErrorResponse {
        public String message;

        public ErrorResponse() {
        }

        public ErrorResponse(String message) {
            this.message = message;
        }
    }
}
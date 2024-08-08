package dev.iansilva.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import dev.iansilva.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    var servelet = request.getServletPath();

    if (servelet.startsWith("/tasks/")) {

      var auth = request.getHeader("Authorization");

      var encodedAuth = auth.substring("Basic".length()).trim();

      byte[] decodedAuth = Base64.getDecoder().decode(encodedAuth);

      var decodedAuthString = new String(decodedAuth);

      String[] credentials = decodedAuthString.split(":");
      String username = credentials[0];
      String password = credentials[1];

      var user = this.userRepository.findByUsername(username);

      if (user == null) {
        response.sendError(401);

        return;
      }

      var verifyPassword = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

      if (!verifyPassword.verified) {
        response.sendError(401);

        return;
      }

      request.setAttribute("userId", user.getId());

      filterChain.doFilter(request, response);

    } else {
      filterChain.doFilter(request, response);
    }
  }

}

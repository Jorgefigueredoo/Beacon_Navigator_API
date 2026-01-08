package com.beaconnavigator.api.config;

import com.beaconnavigator.api.models.Usuario;
import com.beaconnavigator.api.repository.UsuarioRepository;
import com.beaconnavigator.api.security.JwtAuthenticationFilter;
import com.beaconnavigator.api.security.JwtService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    /**
     * Exemplo:
     * app.frontend-url=http://localhost:5173
     * app.frontend-url=https://beaconnavigator.com.br
     */
    @Value("${app.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    /**
     * Cookie settings
     * - Secure=true exige HTTPS (em produção OK). Em DEV (http) você pode setar
     * false via env.
     */
    @Value("${app.auth.cookie-secure:false}")
    private boolean cookieSecure;

    /**
     * Tempo do cookie em segundos (3600 = 1h)
     */
    @Value("${app.auth.cookie-max-age:3600}")
    private int cookieMaxAgeSeconds;

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter,
            JwtService jwtService,
            UsuarioRepository usuarioRepository) throws Exception {

        http
                // Para API com JWT, a sessão fica stateless
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Se você está usando cookie HttpOnly para autenticação, mantenha CSRF
                // habilitado
                // e ignore apenas endpoints que precisam ser "public" (login/callback) ou use
                // token CSRF no front.
                // Aqui deixo CSRF habilitado por padrão e ignoro rotas de auth para
                // simplificar.
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/auth/**",
                        "/oauth2/**",
                        "/login/oauth2/**",
                        "/swagger-ui/**",
                        "/v3/api-docs/**"))

                // CORS precisa estar configurado no CorsConfigurationSource (recomendado).
                // Se você não tiver, crie um CorsConfig e use allowCredentials(true) porque
                // estamos usando cookie.
                .cors(Customizer.withDefaults())

                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // Headers de hardening
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(Customizer.withDefaults())
                // HSTS use em produção com HTTPS. Se estiver em DEV http, deixe desativado via
                // profile.
                // .httpStrictTransportSecurity(hsts ->
                // hsts.includeSubDomains(true).preload(true).maxAgeInSeconds(31536000))
                )

                // 401 e 403 em JSON
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            res.getWriter().write("{\"message\":\"Não autenticado\"}");
                        })
                        .accessDeniedHandler((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            res.getWriter().write("{\"message\":\"Acesso negado\"}");
                        }))

                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/error").permitAll()

                        // Preflight
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Público
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/usuarios").permitAll() // Cadastro
                        .requestMatchers(HttpMethod.GET, "/usuarios/teste").permitAll()

                        // Swagger (recomendo proteger em produção)
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()

                        // uploads públicos (se for realmente necessário)
                        .requestMatchers(HttpMethod.GET, "/uploads/**").permitAll()

                        // OAuth2 endpoints
                        .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()

                        // Todo o resto protegido
                        .anyRequest().authenticated())

                // Login Google OAuth2: cria/obtém usuário e seta cookie HttpOnly

                // Seu filtro JWT deve aceitar token via:
                // 1) Header Authorization: Bearer ...
                // 2) OU cookie "access_token" (recomendado agora)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

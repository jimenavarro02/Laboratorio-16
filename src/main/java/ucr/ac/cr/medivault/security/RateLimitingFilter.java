package ucr.ac.cr.medivault.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitingFilter extends OncePerRequestFilter {

    private static final int LOGIN_LIMIT = 5;
    private static final int API_LIMIT = 30;
    private static final int MAX_TRACKED_IPS = 100_000;

    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> apiBuckets = new ConcurrentHashMap<>();

    private Bucket newBucket(int limit) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(limit, Refill.intervally(limit, Duration.ofMinutes(1))))
                .build();
    }

    private Bucket resolveBucket(Map<String, Bucket> map, String ip, int limit) {
        if (map.size() > MAX_TRACKED_IPS) {
            map.clear();
        }
        return map.computeIfAbsent(ip, k -> newBucket(limit));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String ip = ClientIpResolver.resolve(request);
        Bucket target = null;

        if (path.startsWith("/api/v1/auth/login")) {
            target = resolveBucket(loginBuckets, ip, LOGIN_LIMIT);
        } else if (path.startsWith("/api/v1/expedientes")) {
            target = resolveBucket(apiBuckets, ip, API_LIMIT);
        }

        if (target == null || target.tryConsume(1)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Retry-After", "60");
        String safePath = path.replace("\\", "\\\\").replace("\"", "\\\"");
        String json = """
                {
                  "type": "https://medivault.ucr.ac.cr/rate-limit",
                  "title": "Demasiadas Peticiones",
                  "status": 429,
                  "detail": "Limite superado. Espere 60s.",
                  "instance": "%s"
                }
                """.formatted(safePath);
        response.getWriter().write(json);
    }
}

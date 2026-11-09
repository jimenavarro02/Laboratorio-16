package ucr.ac.cr.medivault.business;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class SecurityAuditorService {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityAuditorService.class);

    private final JdbcTemplate jdbc;

    public SecurityAuditorService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Async
    public void registrar(String username, String ip, String accion,
                          String recurso, int codigoEstado, String detalle) {
        try {
            jdbc.update(
                "INSERT INTO AUDIT_LOGS (username, ip_origen, accion, recurso_solicitado, codigo_estado, detalle_evento) " +
                "VALUES (?, ?, ?, ?, ?, ?)",
                truncar(username, 50),
                truncar(ip == null ? "desconocida" : ip, 45),
                truncar(accion, 50),
                truncar(recurso == null ? "-" : recurso, 255),
                codigoEstado,
                truncar(detalle, 255));
        } catch (Exception e) {
            LOG.error("No se pudo registrar el evento de auditoria", e);
        }
    }

    private String truncar(String valor, int max) {
        if (valor == null) {
            return null;
        }
        return valor.length() <= max ? valor : valor.substring(0, max);
    }
}

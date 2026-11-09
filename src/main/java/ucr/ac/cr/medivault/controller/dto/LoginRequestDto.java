package ucr.ac.cr.medivault.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequestDto(
        @NotBlank(message = "Usuario obligatorio.")
        @Size(min = 4, max = 50, message = "Usuario: 4 a 50 caracteres.")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Solo alfanumericos.")
        String username,

        @NotBlank(message = "Contrasena requerida.")
        @Size(max = 100, message = "Contrasena maximo 100 caracteres.")
        String password
) {}

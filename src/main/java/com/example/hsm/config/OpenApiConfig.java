package com.example.hsm.config;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.*;
import io.swagger.v3.oas.models.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Configures the OpenAPI specification with security scheme and HSM disclaimer. */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Software HSM Emulator API")
                        .version("0.1.0")
                        .description("""
                                Educational software emulator of a Hardware Security Module (HSM).
                                
                                ⚠️  NOT FIPS certified. NOT for production key protection.
                                Keys are protected by software-derived wrapping — not tamper-resistant hardware.
                                See README for limitations and security model.
                                """)
                        .license(new License().name("MIT")))
                .addSecurityItem(new SecurityRequirement().addList("BearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("BearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("HSM token (hsm_tk_...)")));
    }
}

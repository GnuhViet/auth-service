package com.example.demo.authentication.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisteredRequest {
    @JsonProperty("fullName")
    @NotBlank(message = "Full name is mandatory")
    private String fullName;

    @Pattern(regexp = "^[a-zA-Z0-9_]{6,}$",
            message = "username must be min 5 character and not containing special character")
    @NotBlank(message = "Username is mandatory")
    private String username;

    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{4,12}$",
            message = "password must be min 4 and max 12 length containing at least 1 uppercase, 1 lowercase, 1 special character and 1 digit")
    @NotBlank(message = "Password is mandatory")
    private String password;

    //https://www.baeldung.com/java-email-validation-regex
    @Pattern(regexp = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@"
            + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$",
            message = "email is invalid")
    @NotBlank(message = "Email is mandatory")
    private String email;
}

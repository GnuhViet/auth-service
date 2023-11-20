package com.example.demo.authentication.model;


import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserProfileRequest {
    private String fullName;
    @Pattern(regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
            message = "Please enter a valid email address")
    private String email;
    @Pattern(regexp = "^[0-9]{6,}$",
            message = "Phone number must be min 6 digits and valid number")
    private String phoneNumber;
    private String avatar;
}

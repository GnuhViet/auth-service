package com.example.demo.authentication.entities;

import com.example.demo.user.entities.AppUser;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class ConfirmToken {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    @Column(nullable = false)
    private String token;
    private int attempts;
    @Column(nullable = false)
    private LocalDateTime createAt;
    private LocalDateTime expiresAt;
    private LocalDateTime confirmedAt;

    @ManyToOne
    @JoinColumn(
            nullable = false,
            unique = true,
            name = "app_user_id"
    )
    private AppUser appUser;
}

package com.example.demo.user.entities;

import com.example.demo.user.constans.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.util.Collection;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    @Column(unique = true)
    private String username;
    @Column(unique = true)
    private String email;
    private String fullName;
    private String password;
    private String status = UserStatus.Constants.ACTIVE;
    @ColumnDefault("0")
    private Boolean verify;
    @Column(unique = true)
    private String phoneNumber;
    @ManyToMany(fetch =  FetchType.LAZY)
    private Collection<Role> roles;
}


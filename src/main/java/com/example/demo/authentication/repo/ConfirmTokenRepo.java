package com.example.demo.authentication.repo;

import com.example.demo.authentication.entities.ConfirmToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface ConfirmTokenRepo extends JpaRepository<ConfirmToken, String> {
    Optional<ConfirmToken> findByToken(String token);

    @Transactional
    @Query(
            value = "select * from CONFIRM_TOKEN where APP_USER_ID = :userId",
            nativeQuery = true
    )
    Optional<ConfirmToken> findByAppUser_Id(@Param("userId") String userId);
}

package com.caleb.backend.repository;

import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.RefreshToken;
import com.caleb.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByTokenValue(String tokenValue);

    @Modifying
    @Transactional
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user AND r.client = :client")
    void revokeUserTokensForClient(@Param("user") User user, @Param("client") OAuthClient client);
}
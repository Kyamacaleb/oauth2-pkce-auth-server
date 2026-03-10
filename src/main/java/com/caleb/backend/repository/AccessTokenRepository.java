package com.caleb.backend.repository;

import com.caleb.backend.model.AccessToken;
import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {
    Optional<AccessToken> findByTokenValue(String tokenValue);

    @Modifying
    @Transactional
    @Query("UPDATE AccessToken a SET a.revoked = true WHERE a.user = :user AND a.client = :client")
    void revokeUserTokensForClient(@Param("user") User user, @Param("client") OAuthClient client);

}
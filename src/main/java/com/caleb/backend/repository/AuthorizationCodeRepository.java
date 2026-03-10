package com.caleb.backend.repository;

import com.caleb.backend.model.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    @Query("SELECT a FROM AuthorizationCode a JOIN FETCH a.client JOIN FETCH a.user WHERE a.code = :code")
    Optional<AuthorizationCode> findByCode(@Param("code") String code);
    @Query("SELECT a FROM AuthorizationCode a JOIN FETCH a.client JOIN FETCH a.user WHERE a.id = :id")
    Optional<AuthorizationCode> findById(@Param("id") Long id);
}
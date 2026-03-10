package com.caleb.backend.repository;

import com.caleb.backend.model.OAuthClient;
import com.caleb.backend.model.User;
import com.caleb.backend.model.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserConsentRepository extends JpaRepository<UserConsent, Long> {
    Optional<UserConsent> findByUserAndClient(User user, OAuthClient client);

}
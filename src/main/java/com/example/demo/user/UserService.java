package com.example.demo.user;

import com.example.demo.aspect.exception.EmptyRequestBodyException;
import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.authentication.model.UserProfileRequest;
import com.example.demo.user.constans.UserRoles;
import com.example.demo.user.constans.UserStatus;
import com.example.demo.user.entities.AppUser;
import com.example.demo.user.entities.Role;
import com.example.demo.user.exceptions.UserAlreadyHaveRoleException;
import com.example.demo.user.repo.RoleRepo;
import com.example.demo.user.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserService implements UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final ModelMapper modelMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Objects.requireNonNull(username, "Username must not be null");

        AppUser user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user == null) {
            throw new UsernameNotFoundException("User not found in the database");
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    private AppUser loadAppUserByUsername(String username) throws UsernameNotFoundException {
        Objects.requireNonNull(username, "Username must not be null");

        AppUser user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user == null) {
            throw new UsernameNotFoundException("User not found in the database");
        }

        return user;
    }

    private AppUser loadAppUserByUserid(String userId) throws UsernameNotFoundException {
        Objects.requireNonNull(userId, "user Id must not be null");

        AppUser user = userRepo.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user == null) {
            throw new UsernameNotFoundException("User not found in the database");
        }

        return user;
    }

    public <T> T getUserDto(String userId, Class<T> dtoType) {
        return modelMapper.map(loadAppUserByUserid(userId), dtoType);
    }

    public boolean existById(String id) {
        return userRepo.existsById(id);
    }

    public String getUserid(String username) {
        return loadAppUserByUsername(username).getId();
    }

    public AppUser getReferenceById(String id) {
        return userRepo.getReferenceById(id);
    }

    public DetailsAppUserDTO saveUser(AppUser user) {
        Objects.requireNonNull(user, "User must not be null");

        return modelMapper.map(userRepo.save(user), DetailsAppUserDTO.class);
    }

    public DetailsAppUserDTO updateUserProfile(UserProfileRequest userProfile, String userId) {
        Objects.requireNonNull(userProfile, "Profile must not be null");
        Objects.requireNonNull(userId, "User id must not be null");
        AppUser user = loadAppUserByUserid(userId);
        modelMapper.map(userProfile, user);
        return modelMapper.map(user, DetailsAppUserDTO.class);
    }

    public DetailsAppUserDTO updateUserPassword(String newPassword, String username) {
        Objects.requireNonNull(newPassword, "Password must not be null");
        Objects.requireNonNull(username, "Username must not be null");
        AppUser user = loadAppUserByUsername(username);
        user.setPassword(newPassword);
        return modelMapper.map(user, DetailsAppUserDTO.class);
    }

    public Role saveRole(Role role) {
        // log.info("Saving new role {} to the database", role.getName());
        Objects.requireNonNull(role, "Role must not be null");

        return roleRepo.save(role);
    }

    public void setAdminRoleToUsers(List<String> usernames) {
        if (usernames.isEmpty()) {
            throw new EmptyRequestBodyException("users is empty");
        }

        usernames.forEach(u -> {
            if (!existByUsername(u)) {
                throw new UsernameNotFoundException("User: " + u +" not found");
            }
            addRoleToUser(u, UserRoles.ROLE_ADMIN);
        });
    }

    public void setUserActive(String userId) {
        Objects.requireNonNull(userId, "User id must not be null");
        AppUser user = loadAppUserByUserid(userId);
        user.setStatus(UserStatus.Active.name());
    }

    public DetailsAppUserDTO addRoleToUser(String username, String roleName) {
        Objects.requireNonNull(username, "Username must not be null");
        Objects.requireNonNull(roleName, "Role name must not be null");


        AppUser user = loadAppUserByUsername(username);
        Role role = roleRepo.findByName(roleName).orElseThrow();

        if (user.getRoles() != null) {
            if (user.getRoles().contains(role)) {
                throw new UserAlreadyHaveRoleException(username + " already have the role: " + roleName);
            }
            user.getRoles().add(role);
        } else {
            user.setRoles(new ArrayList<>());
            user.getRoles().add(role);
        }

        return modelMapper.map(user, DetailsAppUserDTO.class);
    }

    public List<DetailsAppUserDTO> getAllUsers() {
        return userRepo.findAll()
                .stream()
                .map(obj -> modelMapper.map(obj, DetailsAppUserDTO.class))
                .collect(Collectors.toList());
    }

    public <T> List<T> getAllUsers(Pageable page, Class<T> dtoType) {
        List<AppUser> res = userRepo.findAll(page).getContent();
        return userRepo.findAll(page).getContent()
                .stream()
                .map(obj -> modelMapper.map(obj, dtoType))
                .collect(Collectors.toList());
    }

    public long countUser() {
        return userRepo.count();
    }

    public boolean existByUsername(String username) {
        return userRepo.existsByUsername(username);
    }

    public boolean existByEmail(String email) {
        return userRepo.existsByEmail(email);
    }

    public boolean existByPhone() {
        return false;
    }

}

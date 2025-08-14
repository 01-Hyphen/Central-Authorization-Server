package com.auth.service;

import com.auth.dto.UserObjDto;
import com.auth.dto.UserRegistrationEvent;
import com.auth.entity.RoleObj;
import com.auth.entity.UserObj;
import com.auth.exception.EntityNotFoundException;
import com.auth.mapper.UserObjMapper;
import com.auth.repo.RoleObjRepo;
import com.auth.repo.UserObjRepo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImpl {
    @Autowired
    private UserObjRepo userObjRepo;

    @Autowired
    private RoleObjRepo roleObjRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    StreamBridge streamBridge;

    public void createUser(UserObjDto userObjDto, List<String> roles){
        Optional<UserObj> op = userObjRepo.findByEmail(userObjDto.getEmail());
        if(op.isPresent()){
            throw  new EntityNotFoundException("User",userObjDto.getEmail(),"email");
        }
//        RoleObj roleObj = roleObjRepo.findByRoleName("USER").orElseThrow(()-> new EntityNotFoundException("Role","USER","role"));
       List<RoleObj> roleObjs = roles.stream().map(r-> roleObjRepo.findByRoleName(r)
               .orElseThrow(()-> new EntityNotFoundException("Role",r,"role" )))
               .toList();
        UserObj userObj = UserObjMapper.userDtoToUser(userObjDto,new UserObj());
        String encodedPwd = passwordEncoder.encode(userObjDto.getPassword());
        userObj.setPassword(encodedPwd);
        userObj.getRoles().addAll(roleObjs);
        UserObj userObj1 = userObjRepo.save(userObj);
        UserRegistrationEvent userRegistrationEvent = new UserRegistrationEvent(userObj1.getUserId(),userObj1.getEmail(),roles);
        boolean send = streamBridge.send("user-registration", userRegistrationEvent);
        System.out.println(send);

    }
}

package com.itheima.security;

import com.itheima.health.pojo.Permission;
import com.itheima.health.pojo.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserService implements UserDetailsService {
    /**
     * 获取认证用户信息 (用户名，密码，权限集合)
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 从数据库查询，通过用户名来查询
        com.itheima.health.pojo.User user = findByUsername(username);
        if(null == user){
            return null;
        }
        // 返回用户的信息 (用户名，密码，权限集合)
        //String username,  用户名
        //String password,  密码
        //Collection<? extends GrantedAuthority> authorities 用户的权限集合
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        // 授权用户的角色与权限
        Set<Role> userRoles = user.getRoles();
        if(null != userRoles){
            for (Role role : userRoles) {
                SimpleGrantedAuthority sgai = new SimpleGrantedAuthority(role.getKeyword());
                // 授予角色
                authorities.add(sgai);
                // 角色下有权限
                Set<Permission> permissions = role.getPermissions();
                if(null != permissions){
                    for (Permission permission : permissions) {
                        // 授予权限
                        authorities.add(new SimpleGrantedAuthority(permission.getKeyword()));
                    }
                }
            }
        }
        // 如果密码是密文，就不能用noop, 用 bcrypt，或者配置文件中配置加载器
        User securityUser = new User(username, user.getPassword(),authorities);
        return securityUser;
    }

    /**
     * 这个用户admin/admin, 有ROLE_ADMIN角色，角色下有ADD_CHECKITEM权限
     * 假设从数据库查询
     * @param username
     * @return
     */
    private com.itheima.health.pojo.User findByUsername (String username){
        if("admin".equals(username)) {
            com.itheima.health.pojo.User user = new com.itheima.health.pojo.User();
            user.setUsername("admin");
            // 使用密文
            user.setPassword("$2a$10$u/BcsUUqZNWUxdmDhbnoeeobJy6IBsL1Gn/S0dMxI2RbSgnMKJ.4a");

            // 角色
            Role role = new Role();
            role.setKeyword("ROLE_ADMIN");

            // 权限
            Permission permission = new Permission();
            permission.setKeyword("ADD_CHECKITEM");

            // 给角色添加权限
            role.getPermissions().add(permission);

            // 把角色放进集合
            Set<Role> roleList = new HashSet<Role>();
            roleList.add(role);

            role = new Role();
            role.setKeyword("ABC");
            roleList.add(role);

            // 设置用户的角色
            user.setRoles(roleList);
            return user;
        }
        return null;
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // 加密
        //System.out.println(encoder.encode("1234"));
        //System.out.println(encoder.encode("1234"));
        //System.out.println(encoder.encode("1234"));

        // 验证密码
        // 第1个 为明文
        // 第2个 为密文
        System.out.println(encoder.matches("1234", "$2a$10$H0FGS7LPDDHfXONVGLQUu.xe/MXW8JtzzHr3XkwFK59rVMDeEsWBG"));
        System.out.println(encoder.matches("1234", "$2a$10$EzyuHV1dhaQ4hr3al5w0IO78ZPIcWCi1w9LqP3Wo8mPkk73UL7qkO"));
        System.out.println(encoder.matches("1234", "$2a$10$9Gxn3nbf1fbEMXbrWvLb3ODKAOP0lYe0GvFRNEPfW5pqjgiYQ2R3m"));
        System.out.println(encoder.matches("1234", "$2a$10$u/BcsUUqZNWUxdmDhbnoeeobJy6IBsL1Gn/S0dMxI2RbSgnMKJ.4a"));
    }
}

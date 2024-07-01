#User
##Ý nghĩa: Đối tượng User đại diện cho người dùng trong hệ thống, chứa các thông tin như tên đăng nhập, mật khẩu, và các quyền hạn (authorities).
##Chức năng: Lưu trữ và quản lý thông tin người dùng để phục vụ cho quá trình xác thực và phân quyền.
##Các method chính:
###withUsername(String username): Tạo một đối tượng User với tên đăng nhập.
###password(String password): Thiết lập mật khẩu cho User.
###roles(String... roles): Thiết lập các vai trò (roles) cho User.
##Code Demo:
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.withUsername("user")
                   .password("{noop}password") 
                   .roles("USER")
                   .build();
    }
}
#UserDetails
##Ý nghĩa: UserDetails là một interface cung cấp các phương thức để lấy thông tin người dùng cần thiết cho việc xác thực và phân quyền.
##Chức năng: Cung cấp thông tin chi tiết về người dùng như tên đăng nhập, mật khẩu, và các quyền hạn.
##Các method chính:
###getAuthorities(): Trả về danh sách các quyền của người dùng.
###getPassword(): Trả về mật khẩu của người dùng.
###getUsername(): Trả về tên đăng nhập của người dùng.
###isAccountNonExpired(): Kiểm tra xem tài khoản có hết hạn hay không.
###isAccountNonLocked(): Kiểm tra xem tài khoản có bị khóa hay không.
###isCredentialsNonExpired(): Kiểm tra xem thông tin xác thực có hết hạn hay không.
###isEnabled(): Kiểm tra xem tài khoản có được kích hoạt hay không.
##Code Demo:
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class MyUserDetails implements UserDetails {
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
#UserDetailsService
##Ý nghĩa: UserDetailsService là một interface cung cấp phương thức loadUserByUsername(String username) để lấy thông tin người dùng từ một nguồn dữ liệu (ví dụ: database).
##Chức năng: Tìm kiếm và trả về thông tin người dùng dựa trên tên đăng nhập.
##Các method chính:
###loadUserByUsername(String username): Tìm kiếm và trả về thông tin người dùng dựa trên tên đăng nhập.
##Code Demo:
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.withUsername("user")
                   .password("{noop}password")
                   .roles("USER")
                   .build();
    }
}
#PasswordEncoder
##Ý nghĩa: PasswordEncoder là một interface cung cấp các phương thức để mã hóa và kiểm tra mật khẩu.
##Chức năng: Mã hóa mật khẩu trước khi lưu trữ và kiểm tra mật khẩu khi xác thực.
##Các method chính:
###encode(CharSequence rawPassword): Mã hóa mật khẩu.
###matches(CharSequence rawPassword, String encodedPassword): Kiểm tra mật khẩu.
##Code Demo:
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MyPasswordEncoder {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
#AuthenticationProvider
##Ý nghĩa: AuthenticationProvider là một interface cung cấp phương thức authenticate(Authentication authentication) để xác thực người dùng.
##Chức năng: Xác thực thông tin người dùng và trả về đối tượng Authentication nếu thành công.
##Các method chính:
###authenticate(Authentication authentication): Xác thực thông tin người dùng.
###supports(Class<?> authentication): Kiểm tra xem loại xác thực nào được hỗ trợ.
##Code Demo:
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails user = userDetailsService.loadUserByUsername(username);

        if (passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
        } else {
            throw new AuthenticationException("Authentication failed") {};
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
#SecurityContextHolder
##Ý nghĩa: SecurityContextHolder là một lớp tiện ích cung cấp quyền truy cập vào SecurityContext, nơi lưu trữ thông tin xác thực của người dùng hiện tại.
##Chức năng: Lưu trữ và cung cấp thông tin xác thực của người dùng hiện tại trong toàn bộ ứng dụng.
##Các method chính:
###getContext(): Trả về SecurityContext hiện tại.
###setContext(SecurityContext context): Thiết lập SecurityContext hiện tại.
###clearContext(): Xóa SecurityContext hiện tại.
##Code Demo:
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtil {
    public static String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : null;
    }
}

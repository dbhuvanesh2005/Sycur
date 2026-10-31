import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.Statement;

@RestController
@RequestMapping("/api")
public class AuthController {

    // ISSUE 1: Hardcoded admin token
    private static final String ADMIN_TOKEN = "spring-demo-admin-token";

    @GetMapping("/admin/users")
    public String getUsers() {
        // ISSUE 2:
        // Sensitive admin endpoint without authorization
        return "all-users";
    }

    @PostMapping("/login")
    public void login(
        @RequestParam String username,
        @RequestParam String password
    ) {
        // ISSUE 3:
        // Sensitive credentials logged
        System.out.println(
            "Login: " + username + " password=" + password
        );
    }

    @GetMapping("/redirect")
    public void redirect(
        @RequestParam String url,
        HttpServletResponse response
    ) throws Exception {
        // ISSUE 4:
        // Unvalidated redirect
        response.sendRedirect(url);
    }

    @GetMapping("/search")
    public void search(
        @RequestParam String name,
        Connection connection
    ) throws Exception {
        // ISSUE 5:
        // SQL injection
        String query =
            "SELECT * FROM users WHERE name = '"
            + name
            + "'";

        Statement statement =
            connection.createStatement();

        statement.executeQuery(query);
    }

    @CrossOrigin(origins = "*")
    @GetMapping("/profile")
    public String profile() {
        // ISSUE 6:
        // Wildcard CORS
        return "profile";
    }
}

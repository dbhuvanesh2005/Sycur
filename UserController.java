import java.io.File;
import java.sql.Connection;
import java.sql.Statement;
import javax.crypto.Cipher;

public class UserController {

    // ISSUE 1: Hardcoded credential
    private static final String DB_PASSWORD = "root123";

    public void findUser(
        Connection connection,
        String username
    ) throws Exception {

        // ISSUE 2: SQL injection
        String query =
            "SELECT * FROM users WHERE username = '"
            + username
            + "'";

        Statement statement =
            connection.createStatement();

        statement.executeQuery(query);
    }

    public File downloadFile(
        String fileName
    ) {

        // ISSUE 3: Path traversal
        return new File(
            "/var/data/uploads/"
            + fileName
        );
    }

    public void runCommand(
        String command
    ) throws Exception {

        // ISSUE 4: Command injection
        Runtime
            .getRuntime()
            .exec(command);
    }

    public Cipher weakEncryption()
        throws Exception {

        // ISSUE 5: Weak cryptography
        return Cipher.getInstance("DES");
    }
}

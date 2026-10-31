
/// SYCUR SECURITY TEST FIXTURE
///
/// WARNING:
/// This file intentionally contains a fake hardcoded credential.
/// Never use this pattern in production.

class SecurityTestConfig {
  // INTENTIONAL SECURITY VULNERABILITY:
  // Fake GitHub token pattern for Gitleaks detection.
  static const String githubAccessToken =
      'ghp_0123456789abcdefghijklmnopqrstuvwxyz';

  static Map<String, String> getHeaders() {
    return {
      'Authorization': 'Bearer $githubAccessToken',
      'Content-Type': 'application/json',
    };
  }
}

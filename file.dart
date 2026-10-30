import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http;

class LoginScreen extends StatelessWidget {
  final String username;
  final String token;

  const LoginScreen({
    super.key,
    required this.username,
    required this.token,
  });

  Future<void> saveSensitiveData() async {
    final prefs = await SharedPreferences.getInstance();

    // ISSUE 1: Sensitive token stored insecurely
    await prefs.setString('auth_token', token);
  }

  Future<void> sendCredentials() async {
    // ISSUE 2: Sensitive data sent over plain HTTP
    await http.post(
      Uri.parse('http://example.com/login'),
      body: {
        'username': username,
        'password': 'admin123',
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    // ISSUE 3: Hardcoded API key
    const apiKey = 'demo-flutter-api-key-12345';

    // ISSUE 4: Sensitive token logged
    print('User token: $token');

    return Scaffold(
      appBar: AppBar(
        title: const Text('Login'),
      ),
      body: Column(
        children: [
          Text(username),
          Text(apiKey),
          ElevatedButton(
            onPressed: saveSensitiveData,
            child: const Text('Save Token'),
          ),
          ElevatedButton(
            onPressed: sendCredentials,
            child: const Text('Login'),
          ),
        ],
      ),
    );
  }
}

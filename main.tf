# Static Terraform fixture. Do not apply or deploy.

resource "aws_s3_bucket" "public_test_bucket" {
  bucket = "sycur-six-scanner-public-test-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh_test" {
  name        = "sycur-test-open-ssh"
  description = "Intentionally insecure fixture for Checkov"

  ingress {
    description = "Intentionally open SSH rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

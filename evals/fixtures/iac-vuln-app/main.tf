# Fixture: intentionally vulnerable Terraform. FAKE data only.
provider "aws" {
  region = "eu-west-1"
}

resource "aws_security_group" "api" {
  name = "shop-api"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SEC-2a: SSH open to the world
  }
}

resource "aws_db_instance" "shop" {
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = false       # SEC-2b: DB unencrypted at rest
  username          = "admin"
  password          = "Fake4EvalsDoNotUse" # SEC-2c: hardcoded DB password
}

resource "aws_launch_template" "fetcher" {
  image_id      = "ami-fake123"
  instance_type = "t3.small"

  metadata_options {             # SEC-2d: IMDSv1 still allowed on a URL-fetching workload
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  user_data = <<-EOF
    #!/bin/bash
    curl -sSL https://install.example-fake.com/agent.sh | bash # SEC-2e: curl | sh in bootstrap
  EOF
}

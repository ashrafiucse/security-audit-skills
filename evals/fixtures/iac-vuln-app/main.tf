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

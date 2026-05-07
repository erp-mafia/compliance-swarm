resource "aws_db_instance" "primary" {
  identifier        = "primary"
  storage_encrypted = false       # checkov CKV_AWS_16
  allocated_storage = 20
  engine            = "postgres"
}

resource "aws_s3_bucket" "data" {
  bucket = "dirty-fixture"
  acl    = "public-read"           # checkov CKV_AWS_19
}

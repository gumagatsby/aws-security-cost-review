# Every rule that can be read from Terraform should fire on this file, once each.

resource "aws_s3_bucket" "uploads" {
  bucket = "example-uploads"
}

resource "aws_db_instance" "orders" {
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "app"
  password                = "hunter2hunter2"
  publicly_accessible     = true
  backup_retention_period = 0
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role_policy" "admin" {
  role = "app"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  root_block_device {
    volume_type = "gp2"
  }
}

resource "aws_lambda_function_url" "api" {
  function_name      = "api"
  authorization_type = "NONE"
}

resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name = "/app"
}

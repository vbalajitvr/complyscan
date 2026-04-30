resource "aws_iam_role" "lambda_bedrock" {
  name = "lambda-bedrock"
  assume_role_policy = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }]
    }
  EOT
}

resource "aws_iam_role_policy" "invoke_bedrock" {
  name = "invoke-bedrock"
  role = aws_iam_role.lambda_bedrock.id
  policy = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        "Resource": "*"
      }]
    }
  EOT
}

resource "aws_lambda_function" "rag_handler" {
  function_name = "rag-handler"
  role          = aws_iam_role.lambda_bedrock.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "handler.zip"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}

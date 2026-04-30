data "aws_bedrock_foundation_model" "claude" {
  model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
}

resource "aws_lambda_function" "rag" {
  function_name = "rag"
  role          = "arn:aws:iam::123456789012:role/rag"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "handler.zip"
  environment {
    variables = {
      MODEL_ID = data.aws_bedrock_foundation_model.claude.id
    }
  }
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}

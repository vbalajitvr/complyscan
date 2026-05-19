resource "aws_lambda_function" "api" {
  function_name = "recruiter-api"
  role          = "arn:aws:iam::123456789012:role/lambda"
  handler       = "index.handler"
  runtime       = "python3.11"
}

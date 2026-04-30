data "aws_iam_policy_document" "bedrock_converse" {
  statement {
    effect    = "Allow"
    actions   = ["bedrock:Converse", "bedrock:ConverseStream"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "converse" {
  name   = "bedrock-converse"
  policy = data.aws_iam_policy_document.bedrock_converse.json
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}

resource "aws_iam_policy" "agent_policy" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::bucket/*" }]
  })
}

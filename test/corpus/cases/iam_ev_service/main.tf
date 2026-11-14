resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "arn:aws:s3:::b/*" }]
  })
}

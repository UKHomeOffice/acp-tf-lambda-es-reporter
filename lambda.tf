data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "/tmp/lambda_zip.zip"
  source {
    content  = file("lambda/${var.function_name}.py")
    filename = "${var.function_name}.py"
  }
}

resource "aws_lambda_function" "acp_health_notifier" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  function_name = var.function_name

  handler = "${var.function_name}.main"

  runtime = "python3.8"

  role = aws_iam_role.lambda_role.arn
}

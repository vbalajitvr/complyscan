variable "log_bucket" {
  type    = string
  default = "parent-log-bucket"
}

module "bedrock" {
  source     = "./modules/bedrock"
  log_bucket = var.log_bucket
}

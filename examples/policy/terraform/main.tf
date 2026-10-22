# Пример: одна ВМ размечена, у второй нет service/environment.
resource "vsphere_virtual_machine" "billing_app" {
  name             = "prod-billing-app-07"
  resource_pool_id = data.vsphere_compute_cluster.prod.resource_pool_id
  num_cpus         = 4
  memory           = 8192

  custom_attributes = {
    owner_team  = "billing"
    service     = "billing-core"
    environment = "production"
  }
}

resource "vsphere_virtual_machine" "tmp_test" {
  name             = "tmp-test-01"
  resource_pool_id = data.vsphere_compute_cluster.dev.resource_pool_id
  num_cpus         = 2
  memory           = 2048

  custom_attributes = {
    owner_team = "web"
  }
}

package main

import (
	"github.com/hashicorp/terraform/plugin"
	"terraform-provider-aws/aws"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: aws.Provider})
}

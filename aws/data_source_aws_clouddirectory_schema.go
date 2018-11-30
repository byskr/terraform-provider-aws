package aws

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceAwsClouddirectorySchema() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceClouddirectorySchemaRead,

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cli_input_json": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceClouddirectorySchemaRead(d *schema.ResourceData, meta interface{}) error {
	d.SetId(d.Get("arn").(string))
	return resourceAwsClouddirectorySchemaRead(d, meta)
}

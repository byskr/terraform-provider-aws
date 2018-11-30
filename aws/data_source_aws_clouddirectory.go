package aws

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceAwsClouddirectory() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceClouddirectoryRead,

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"schema_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceClouddirectoryRead(d *schema.ResourceData, meta interface{}) error {
	d.SetId(d.Get("arn").(string))
	return resourceAwsClouddirectoryRead(d, meta)
}

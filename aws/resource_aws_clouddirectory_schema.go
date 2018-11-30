package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/clouddirectory"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAwsClouddirectorySchema() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsClouddirectorySchemaCreate,
		Read:   resourceAwsClouddirectorySchemaRead,
		Update: resourceAwsClouddirectorySchemaUpdate,
		Delete: resourceAwsClouddirectorySchemaDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"cli_input_json": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsClouddirectorySchemaCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).clouddirconn

	var name string
	if v, ok := d.GetOk("name"); ok {
		name = v.(string)
	} else {
		name = resource.UniqueId()
	}

	input := clouddirectory.CreateSchemaInput{}
	input.Name = aws.String(name)

	log.Printf("[DEBUG] Creating Schema: %s", input)

	output, err := conn.CreateSchema(&input)

	if err != nil {
		return err
	}

	d.SetId(*output.SchemaArn)

	jsonInput := clouddirectory.PutSchemaFromJsonInput{}
	jsonInput.SchemaArn = output.SchemaArn
	jsonInput.SetDocument(*aws.String(d.Get("cli_input_json").(string)))

	_, err = conn.PutSchemaFromJson(&jsonInput)

	if err != nil {
		return err
	}

	return resourceAwsClouddirectorySchemaRead(d, meta)
}

func resourceAwsClouddirectorySchemaRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).clouddirconn

	getSchemaAsJsonInput := &clouddirectory.GetSchemaAsJsonInput{
		SchemaArn: aws.String(d.Id()),
	}

	log.Printf("[DEBUG] Getting Schema: %s", getSchemaAsJsonInput)

	// Handle IAM eventual consistency
	var getSchemaOutput *clouddirectory.GetSchemaAsJsonOutput
	err := resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		getSchemaOutput, err = conn.GetSchemaAsJson(getSchemaAsJsonInput)

		if d.IsNewResource() && isAWSErr(err, iam.ErrCodeNoSuchEntityException, "") {
			return resource.RetryableError(err)
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if isAWSErr(err, iam.ErrCodeNoSuchEntityException, "") {
		log.Printf("[WARN] IAM Policy (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("Error reading Schema %s: %s", d.Id(), err)
	}

	if getSchemaOutput == nil {
		log.Printf("[WARN] Schema not found (%s), removing from state", d.Id())
		d.SetId("")
		return nil
	}

	d.Set("name", getSchemaOutput.Name)
	d.Set("cli_input_json", getSchemaOutput.Document)
	d.Set("arn", d.Id())

	return nil
}

func resourceAwsClouddirectorySchemaUpdate(d *schema.ResourceData, meta interface{}) error {

	//	*clouddirectory.UpdateSchemaInput{}
	iamconn := meta.(*AWSClient).iamconn

	if err := ClouddirectorySchemaPruneVersions(d.Id(), iamconn); err != nil {
		return err
	}

	request := &iam.CreatePolicyVersionInput{
		PolicyArn:      aws.String(d.Id()),
		PolicyDocument: aws.String(d.Get("policy").(string)),
		SetAsDefault:   aws.Bool(true),
	}

	if _, err := iamconn.CreatePolicyVersion(request); err != nil {
		return fmt.Errorf("Error updating IAM policy %s: %s", d.Id(), err)
	}

	return resourceAwsClouddirectorySchemaRead(d, meta)
}

func resourceAwsClouddirectorySchemaDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).clouddirconn

	request := &clouddirectory.DeleteSchemaInput{
		SchemaArn: aws.String(d.Id()),
	}

	_, err := conn.DeleteSchema(request)
	if isAWSErr(err, iam.ErrCodeNoSuchEntityException, "") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("Error deleting Schema %s: %#v", d.Id(), err)
	}

	return nil
}

// ClouddirectorySchemaPruneVersions deletes the oldest versions.
//
// Old versions are deleted until there are 4 or less remaining, which means at
// least one more can be created before hitting the maximum of 5.
//
// The default version is never deleted.

func ClouddirectorySchemaPruneVersions(arn string, iamconn *iam.IAM) error {
	versions, err := ClouddirectorySchemaListVersions(arn, iamconn)
	if err != nil {
		return err
	}
	if len(versions) < 5 {
		return nil
	}

	var oldestVersion *iam.PolicyVersion

	for _, version := range versions {
		if *version.IsDefaultVersion {
			continue
		}
		if oldestVersion == nil ||
			version.CreateDate.Before(*oldestVersion.CreateDate) {
			oldestVersion = version
		}
	}

	if err := ClouddirectorySchemaDeleteVersion(arn, *oldestVersion.VersionId, iamconn); err != nil {
		return err
	}
	return nil
}

func ClouddirectorySchemaDeleteNondefaultVersions(arn string, iamconn *iam.IAM) error {
	versions, err := ClouddirectorySchemaListVersions(arn, iamconn)
	if err != nil {
		return err
	}

	for _, version := range versions {
		if *version.IsDefaultVersion {
			continue
		}
		if err := ClouddirectorySchemaDeleteVersion(arn, *version.VersionId, iamconn); err != nil {
			return err
		}
	}

	return nil
}

func ClouddirectorySchemaDeleteVersion(arn, versionID string, iamconn *iam.IAM) error {
	request := &iam.DeletePolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: aws.String(versionID),
	}

	_, err := iamconn.DeletePolicyVersion(request)
	if err != nil {
		return fmt.Errorf("Error deleting version %s from IAM policy %s: %s", versionID, arn, err)
	}
	return nil
}

func ClouddirectorySchemaListVersions(arn string, iamconn *iam.IAM) ([]*iam.PolicyVersion, error) {
	request := &iam.ListPolicyVersionsInput{
		PolicyArn: aws.String(arn),
	}

	response, err := iamconn.ListPolicyVersions(request)
	if err != nil {
		return nil, fmt.Errorf("Error listing versions for IAM policy %s: %s", arn, err)
	}
	return response.Versions, nil
}

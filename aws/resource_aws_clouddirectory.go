package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/clouddirectory"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAwsClouddirectory() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsClouddirectoryCreate,
		Read:   resourceAwsClouddirectoryRead,
		Update: resourceAwsClouddirectoryUpdate,
		Delete: resourceAwsClouddirectoryDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"schema_arn": {
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

func resourceAwsClouddirectoryCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).clouddirconn

	var name string
	if v, ok := d.GetOk("name"); ok {
		name = v.(string)
	} else {
		name = resource.UniqueId()
	}

	request := &clouddirectory.CreateDirectoryInput{
		SchemaArn: aws.String(d.Get("schema_arn").(string)),
		Name:      aws.String(name),
	}

	response, err := conn.CreateDirectory(request)
	if err != nil {
		return fmt.Errorf("Error creating IAM policy %s: %s", name, err)
	}

	d.SetId(*response.DirectoryArn)

	return resourceAwsClouddirectoryRead(d, meta)
}

func resourceAwsClouddirectoryRead(d *schema.ResourceData, meta interface{}) error {
	/*iamconn := meta.(*AWSClient).iamconn

	getPolicyRequest := &iam.GetPolicyInput{
		PolicyArn: aws.String(d.Id()),
	}
	log.Printf("[DEBUG] Getting IAM Policy: %s", getPolicyRequest)

	// Handle IAM eventual consistency
	var getPolicyResponse *iam.GetPolicyOutput
	err := resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		getPolicyResponse, err = iamconn.GetPolicy(getPolicyRequest)

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
		return fmt.Errorf("Error reading IAM policy %s: %s", d.Id(), err)
	}

	if getPolicyResponse == nil || getPolicyResponse.Policy == nil {
		log.Printf("[WARN] IAM Policy (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	d.Set("arn", getPolicyResponse.Policy.Arn)
	d.Set("description", getPolicyResponse.Policy.Description)
	d.Set("name", getPolicyResponse.Policy.PolicyName)
	d.Set("path", getPolicyResponse.Policy.Path)

	// Retrieve policy

	getPolicyVersionRequest := &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(d.Id()),
		VersionId: getPolicyResponse.Policy.DefaultVersionId,
	}
	log.Printf("[DEBUG] Getting IAM Policy Version: %s", getPolicyVersionRequest)

	// Handle IAM eventual consistency
	var getPolicyVersionResponse *iam.GetPolicyVersionOutput
	err = resource.Retry(1*time.Minute, func() *resource.RetryError {
		var err error
		getPolicyVersionResponse, err = iamconn.GetPolicyVersion(getPolicyVersionRequest)

		if isAWSErr(err, iam.ErrCodeNoSuchEntityException, "") {
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
		return fmt.Errorf("Error reading IAM policy version %s: %s", d.Id(), err)
	}

	policy := ""
	if getPolicyVersionResponse != nil && getPolicyVersionResponse.PolicyVersion != nil {
		var err error
		policy, err = url.QueryUnescape(aws.StringValue(getPolicyVersionResponse.PolicyVersion.Document))
		if err != nil {
			return fmt.Errorf("error parsing policy: %s", err)
		}
	}

	d.Set("policy", policy)*/

	return nil
}

func resourceAwsClouddirectoryUpdate(d *schema.ResourceData, meta interface{}) error {
	iamconn := meta.(*AWSClient).iamconn

	if err := iamPolicyPruneVersions(d.Id(), iamconn); err != nil {
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

	return resourceAwsClouddirectoryRead(d, meta)
}

func resourceAwsClouddirectoryDelete(d *schema.ResourceData, meta interface{}) error {
	iamconn := meta.(*AWSClient).iamconn

	if err := iamPolicyDeleteNondefaultVersions(d.Id(), iamconn); err != nil {
		return err
	}

	request := &iam.DeletePolicyInput{
		PolicyArn: aws.String(d.Id()),
	}

	_, err := iamconn.DeletePolicy(request)
	if isAWSErr(err, iam.ErrCodeNoSuchEntityException, "") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("Error deleting IAM policy %s: %#v", d.Id(), err)
	}

	return nil
}

package aws

import (
	"bytes"
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/mutexkv"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	homedir "github.com/mitchellh/go-homedir"
)

// Provider returns a terraform.ResourceProvider.
func Provider() terraform.ResourceProvider {
	// TODO: Move the validation to this, requires conditional schemas
	// TODO: Move the configuration to this, requires validation

	providerName := "r24aws"

	// The actual provider
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["access_key"],
			},

			"secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["secret_key"],
			},

			"profile": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["profile"],
			},

			"assume_role": assumeRoleSchema(),

			"shared_credentials_file": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["shared_credentials_file"],
			},

			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["token"],
			},

			"region": {
				Type:     schema.TypeString,
				Required: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"AWS_REGION",
					"AWS_DEFAULT_REGION",
				}, nil),
				Description:  descriptions["region"],
				InputDefault: "us-east-1",
			},

			"max_retries": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     25,
				Description: descriptions["max_retries"],
			},

			"allowed_account_ids": {
				Type:          schema.TypeSet,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"forbidden_account_ids"},
				Set:           schema.HashString,
			},

			"forbidden_account_ids": {
				Type:          schema.TypeSet,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"allowed_account_ids"},
				Set:           schema.HashString,
			},

			"dynamodb_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["dynamodb_endpoint"],
				Removed:     "Use `dynamodb` inside `endpoints` block instead",
			},

			"kinesis_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: descriptions["kinesis_endpoint"],
				Removed:     "Use `kinesis` inside `endpoints` block instead",
			},

			"endpoints": endpointsSchema(),

			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["insecure"],
			},

			"skip_credentials_validation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["skip_credentials_validation"],
			},

			"skip_get_ec2_platforms": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["skip_get_ec2_platforms"],
			},

			"skip_region_validation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["skip_region_validation"],
			},

			"skip_requesting_account_id": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["skip_requesting_account_id"],
			},

			"skip_metadata_api_check": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["skip_metadata_api_check"],
			},

			"s3_force_path_style": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: descriptions["s3_force_path_style"],
			},
		},

		DataSourcesMap: map[string]*schema.Resource{
			providerName + "_acm_certificate":                    dataSourceAwsAcmCertificate(),
			providerName + "_acmpca_certificate_authority":       dataSourceAwsAcmpcaCertificateAuthority(),
			providerName + "_ami":                                dataSourceAwsAmi(),
			providerName + "_ami_ids":                            dataSourceAwsAmiIds(),
			providerName + "_api_gateway_api_key":                dataSourceAwsApiGatewayApiKey(),
			providerName + "_api_gateway_resource":               dataSourceAwsApiGatewayResource(),
			providerName + "_api_gateway_rest_api":               dataSourceAwsApiGatewayRestApi(),
			providerName + "_arn":                                dataSourceAwsArn(),
			providerName + "_autoscaling_groups":                 dataSourceAwsAutoscalingGroups(),
			providerName + "_availability_zone":                  dataSourceAwsAvailabilityZone(),
			providerName + "_availability_zones":                 dataSourceAwsAvailabilityZones(),
			providerName + "_batch_compute_environment":          dataSourceAwsBatchComputeEnvironment(),
			providerName + "_batch_job_queue":                    dataSourceAwsBatchJobQueue(),
			providerName + "_billing_service_account":            dataSourceAwsBillingServiceAccount(),
			providerName + "_caller_identity":                    dataSourceAwsCallerIdentity(),
			providerName + "_canonical_user_id":                  dataSourceAwsCanonicalUserId(),
			providerName + "_clouddirectory_schema":              dataSourceAwsClouddirectorySchema(),
			providerName + "_clouddirectory":                     dataSourceAwsClouddirectory(),
			providerName + "_cloudformation_export":              dataSourceAwsCloudFormationExport(),
			providerName + "_cloudformation_stack":               dataSourceAwsCloudFormationStack(),
			providerName + "_cloudhsm_v2_cluster":                dataSourceCloudHsm2Cluster(),
			providerName + "_cloudtrail_service_account":         dataSourceAwsCloudTrailServiceAccount(),
			providerName + "_cloudwatch_log_group":               dataSourceAwsCloudwatchLogGroup(),
			providerName + "_cognito_user_pools":                 dataSourceAwsCognitoUserPools(),
			providerName + "_codecommit_repository":              dataSourceAwsCodeCommitRepository(),
			providerName + "_db_cluster_snapshot":                dataSourceAwsDbClusterSnapshot(),
			providerName + "_db_event_categories":                dataSourceAwsDbEventCategories(),
			providerName + "_db_instance":                        dataSourceAwsDbInstance(),
			providerName + "_db_snapshot":                        dataSourceAwsDbSnapshot(),
			providerName + "_dx_gateway":                         dataSourceAwsDxGateway(),
			providerName + "_dynamodb_table":                     dataSourceAwsDynamoDbTable(),
			providerName + "_ebs_snapshot":                       dataSourceAwsEbsSnapshot(),
			providerName + "_ebs_snapshot_ids":                   dataSourceAwsEbsSnapshotIds(),
			providerName + "_ebs_volume":                         dataSourceAwsEbsVolume(),
			providerName + "_ec2_transit_gateway":                dataSourceAwsEc2TransitGateway(),
			providerName + "_ec2_transit_gateway_route_table":    dataSourceAwsEc2TransitGatewayRouteTable(),
			providerName + "_ec2_transit_gateway_vpc_attachment": dataSourceAwsEc2TransitGatewayVpcAttachment(),
			providerName + "_ecr_repository":                     dataSourceAwsEcrRepository(),
			providerName + "_ecs_cluster":                        dataSourceAwsEcsCluster(),
			providerName + "_ecs_container_definition":           dataSourceAwsEcsContainerDefinition(),
			providerName + "_ecs_service":                        dataSourceAwsEcsService(),
			providerName + "_ecs_task_definition":                dataSourceAwsEcsTaskDefinition(),
			providerName + "_efs_file_system":                    dataSourceAwsEfsFileSystem(),
			providerName + "_efs_mount_target":                   dataSourceAwsEfsMountTarget(),
			providerName + "_eip":                                dataSourceAwsEip(),
			providerName + "_eks_cluster":                        dataSourceAwsEksCluster(),
			providerName + "_elastic_beanstalk_hosted_zone":      dataSourceAwsElasticBeanstalkHostedZone(),
			providerName + "_elastic_beanstalk_solution_stack":   dataSourceAwsElasticBeanstalkSolutionStack(),
			providerName + "_elasticache_cluster":                dataSourceAwsElastiCacheCluster(),
			providerName + "_elb":                                dataSourceAwsElb(),
			providerName + "_elasticache_replication_group":      dataSourceAwsElasticacheReplicationGroup(),
			providerName + "_elb_hosted_zone_id":                 dataSourceAwsElbHostedZoneId(),
			providerName + "_elb_service_account":                dataSourceAwsElbServiceAccount(),
			providerName + "_glue_script":                        dataSourceAwsGlueScript(),
			providerName + "_iam_account_alias":                  dataSourceAwsIamAccountAlias(),
			providerName + "_iam_group":                          dataSourceAwsIAMGroup(),
			providerName + "_iam_instance_profile":               dataSourceAwsIAMInstanceProfile(),
			providerName + "_iam_policy":                         dataSourceAwsIAMPolicy(),
			providerName + "_iam_policy_document":                dataSourceAwsIamPolicyDocument(),
			providerName + "_iam_role":                           dataSourceAwsIAMRole(),
			providerName + "_iam_server_certificate":             dataSourceAwsIAMServerCertificate(),
			providerName + "_iam_user":                           dataSourceAwsIAMUser(),
			providerName + "_internet_gateway":                   dataSourceAwsInternetGateway(),
			providerName + "_iot_endpoint":                       dataSourceAwsIotEndpoint(),
			providerName + "_inspector_rules_packages":           dataSourceAwsInspectorRulesPackages(),
			providerName + "_instance":                           dataSourceAwsInstance(),
			providerName + "_instances":                          dataSourceAwsInstances(),
			providerName + "_ip_ranges":                          dataSourceAwsIPRanges(),
			providerName + "_kinesis_stream":                     dataSourceAwsKinesisStream(),
			providerName + "_kms_alias":                          dataSourceAwsKmsAlias(),
			providerName + "_kms_ciphertext":                     dataSourceAwsKmsCiphertext(),
			providerName + "_kms_key":                            dataSourceAwsKmsKey(),
			providerName + "_kms_secret":                         dataSourceAwsKmsSecret(),
			providerName + "_kms_secrets":                        dataSourceAwsKmsSecrets(),
			providerName + "_lambda_function":                    dataSourceAwsLambdaFunction(),
			providerName + "_lambda_invocation":                  dataSourceAwsLambdaInvocation(),
			providerName + "_launch_configuration":               dataSourceAwsLaunchConfiguration(),
			providerName + "_launch_template":                    dataSourceAwsLaunchTemplate(),
			providerName + "_mq_broker":                          dataSourceAwsMqBroker(),
			providerName + "_nat_gateway":                        dataSourceAwsNatGateway(),
			providerName + "_network_acls":                       dataSourceAwsNetworkAcls(),
			providerName + "_network_interface":                  dataSourceAwsNetworkInterface(),
			providerName + "_network_interfaces":                 dataSourceAwsNetworkInterfaces(),
			providerName + "_partition":                          dataSourceAwsPartition(),
			providerName + "_prefix_list":                        dataSourceAwsPrefixList(),
			providerName + "_pricing_product":                    dataSourceAwsPricingProduct(),
			providerName + "_rds_cluster":                        dataSourceAwsRdsCluster(),
			providerName + "_redshift_cluster":                   dataSourceAwsRedshiftCluster(),
			providerName + "_redshift_service_account":           dataSourceAwsRedshiftServiceAccount(),
			providerName + "_region":                             dataSourceAwsRegion(),
			providerName + "_route":                              dataSourceAwsRoute(),
			providerName + "_route_table":                        dataSourceAwsRouteTable(),
			providerName + "_route_tables":                       dataSourceAwsRouteTables(),
			providerName + "_route53_delegation_set":             dataSourceAwsDelegationSet(),
			providerName + "_route53_zone":                       dataSourceAwsRoute53Zone(),
			providerName + "_s3_bucket":                          dataSourceAwsS3Bucket(),
			providerName + "_s3_bucket_object":                   dataSourceAwsS3BucketObject(),
			providerName + "_secretsmanager_secret":              dataSourceAwsSecretsManagerSecret(),
			providerName + "_secretsmanager_secret_version":      dataSourceAwsSecretsManagerSecretVersion(),
			providerName + "_sns_topic":                          dataSourceAwsSnsTopic(),
			providerName + "_sqs_queue":                          dataSourceAwsSqsQueue(),
			providerName + "_ssm_document":                       dataSourceAwsSsmDocument(),
			providerName + "_ssm_parameter":                      dataSourceAwsSsmParameter(),
			providerName + "_storagegateway_local_disk":          dataSourceAwsStorageGatewayLocalDisk(),
			providerName + "_subnet":                             dataSourceAwsSubnet(),
			providerName + "_subnet_ids":                         dataSourceAwsSubnetIDs(),
			providerName + "_vpcs":                               dataSourceAwsVpcs(),
			providerName + "_security_group":                     dataSourceAwsSecurityGroup(),
			providerName + "_security_groups":                    dataSourceAwsSecurityGroups(),
			providerName + "_vpc":                                dataSourceAwsVpc(),
			providerName + "_vpc_dhcp_options":                   dataSourceAwsVpcDhcpOptions(),
			providerName + "_vpc_endpoint":                       dataSourceAwsVpcEndpoint(),
			providerName + "_vpc_endpoint_service":               dataSourceAwsVpcEndpointService(),
			providerName + "_vpc_peering_connection":             dataSourceAwsVpcPeeringConnection(),
			providerName + "_vpn_gateway":                        dataSourceAwsVpnGateway(),
			providerName + "_workspaces_bundle":                  dataSourceAwsWorkspaceBundle(),

			// Adding the Aliases for the ALB -> LB Rename
			providerName + "_lb":               dataSourceAwsLb(),
			providerName + "_alb":              dataSourceAwsLb(),
			providerName + "_lb_listener":      dataSourceAwsLbListener(),
			providerName + "_alb_listener":     dataSourceAwsLbListener(),
			providerName + "_lb_target_group":  dataSourceAwsLbTargetGroup(),
			providerName + "_alb_target_group": dataSourceAwsLbTargetGroup(),
		},

		ResourcesMap: map[string]*schema.Resource{
			providerName + "_acm_certificate":                              resourceAwsAcmCertificate(),
			providerName + "_acm_certificate_validation":                   resourceAwsAcmCertificateValidation(),
			providerName + "_acmpca_certificate_authority":                 resourceAwsAcmpcaCertificateAuthority(),
			providerName + "_ami":                                          resourceAwsAmi(),
			providerName + "_ami_copy":                                     resourceAwsAmiCopy(),
			providerName + "_ami_from_instance":                            resourceAwsAmiFromInstance(),
			providerName + "_ami_launch_permission":                        resourceAwsAmiLaunchPermission(),
			providerName + "_api_gateway_account":                          resourceAwsApiGatewayAccount(),
			providerName + "_api_gateway_api_key":                          resourceAwsApiGatewayApiKey(),
			providerName + "_api_gateway_authorizer":                       resourceAwsApiGatewayAuthorizer(),
			providerName + "_api_gateway_base_path_mapping":                resourceAwsApiGatewayBasePathMapping(),
			providerName + "_api_gateway_client_certificate":               resourceAwsApiGatewayClientCertificate(),
			providerName + "_api_gateway_deployment":                       resourceAwsApiGatewayDeployment(),
			providerName + "_api_gateway_documentation_part":               resourceAwsApiGatewayDocumentationPart(),
			providerName + "_api_gateway_documentation_version":            resourceAwsApiGatewayDocumentationVersion(),
			providerName + "_api_gateway_domain_name":                      resourceAwsApiGatewayDomainName(),
			providerName + "_api_gateway_gateway_response":                 resourceAwsApiGatewayGatewayResponse(),
			providerName + "_api_gateway_integration":                      resourceAwsApiGatewayIntegration(),
			providerName + "_api_gateway_integration_response":             resourceAwsApiGatewayIntegrationResponse(),
			providerName + "_api_gateway_method":                           resourceAwsApiGatewayMethod(),
			providerName + "_api_gateway_method_response":                  resourceAwsApiGatewayMethodResponse(),
			providerName + "_api_gateway_method_settings":                  resourceAwsApiGatewayMethodSettings(),
			providerName + "_api_gateway_model":                            resourceAwsApiGatewayModel(),
			providerName + "_api_gateway_request_validator":                resourceAwsApiGatewayRequestValidator(),
			providerName + "_api_gateway_resource":                         resourceAwsApiGatewayResource(),
			providerName + "_api_gateway_rest_api":                         resourceAwsApiGatewayRestApi(),
			providerName + "_api_gateway_stage":                            resourceAwsApiGatewayStage(),
			providerName + "_api_gateway_usage_plan":                       resourceAwsApiGatewayUsagePlan(),
			providerName + "_api_gateway_usage_plan_key":                   resourceAwsApiGatewayUsagePlanKey(),
			providerName + "_api_gateway_vpc_link":                         resourceAwsApiGatewayVpcLink(),
			providerName + "_app_cookie_stickiness_policy":                 resourceAwsAppCookieStickinessPolicy(),
			providerName + "_appautoscaling_target":                        resourceAwsAppautoscalingTarget(),
			providerName + "_appautoscaling_policy":                        resourceAwsAppautoscalingPolicy(),
			providerName + "_appautoscaling_scheduled_action":              resourceAwsAppautoscalingScheduledAction(),
			providerName + "_appsync_api_key":                              resourceAwsAppsyncApiKey(),
			providerName + "_appsync_datasource":                           resourceAwsAppsyncDatasource(),
			providerName + "_appsync_graphql_api":                          resourceAwsAppsyncGraphqlApi(),
			providerName + "_athena_database":                              resourceAwsAthenaDatabase(),
			providerName + "_athena_named_query":                           resourceAwsAthenaNamedQuery(),
			providerName + "_autoscaling_attachment":                       resourceAwsAutoscalingAttachment(),
			providerName + "_autoscaling_group":                            resourceAwsAutoscalingGroup(),
			providerName + "_autoscaling_lifecycle_hook":                   resourceAwsAutoscalingLifecycleHook(),
			providerName + "_autoscaling_notification":                     resourceAwsAutoscalingNotification(),
			providerName + "_autoscaling_policy":                           resourceAwsAutoscalingPolicy(),
			providerName + "_autoscaling_schedule":                         resourceAwsAutoscalingSchedule(),
			providerName + "_budgets_budget":                               resourceAwsBudgetsBudget(),
			providerName + "_cloud9_environment_ec2":                       resourceAwsCloud9EnvironmentEc2(),
			providerName + "_clouddirectory_schema":                        resourceAwsClouddirectorySchema(),
			providerName + "_clouddirectory":                               resourceAwsClouddirectory(),
			providerName + "_cloudformation_stack":                         resourceAwsCloudFormationStack(),
			providerName + "_cloudfront_distribution":                      resourceAwsCloudFrontDistribution(),
			providerName + "_cloudfront_origin_access_identity":            resourceAwsCloudFrontOriginAccessIdentity(),
			providerName + "_cloudfront_public_key":                        resourceAwsCloudFrontPublicKey(),
			providerName + "_cloudtrail":                                   resourceAwsCloudTrail(),
			providerName + "_cloudwatch_event_permission":                  resourceAwsCloudWatchEventPermission(),
			providerName + "_cloudwatch_event_rule":                        resourceAwsCloudWatchEventRule(),
			providerName + "_cloudwatch_event_target":                      resourceAwsCloudWatchEventTarget(),
			providerName + "_cloudwatch_log_destination":                   resourceAwsCloudWatchLogDestination(),
			providerName + "_cloudwatch_log_destination_policy":            resourceAwsCloudWatchLogDestinationPolicy(),
			providerName + "_cloudwatch_log_group":                         resourceAwsCloudWatchLogGroup(),
			providerName + "_cloudwatch_log_metric_filter":                 resourceAwsCloudWatchLogMetricFilter(),
			providerName + "_cloudwatch_log_resource_policy":               resourceAwsCloudWatchLogResourcePolicy(),
			providerName + "_cloudwatch_log_stream":                        resourceAwsCloudWatchLogStream(),
			providerName + "_cloudwatch_log_subscription_filter":           resourceAwsCloudwatchLogSubscriptionFilter(),
			providerName + "_config_aggregate_authorization":               resourceAwsConfigAggregateAuthorization(),
			providerName + "_config_config_rule":                           resourceAwsConfigConfigRule(),
			providerName + "_config_configuration_aggregator":              resourceAwsConfigConfigurationAggregator(),
			providerName + "_config_configuration_recorder":                resourceAwsConfigConfigurationRecorder(),
			providerName + "_config_configuration_recorder_status":         resourceAwsConfigConfigurationRecorderStatus(),
			providerName + "_config_delivery_channel":                      resourceAwsConfigDeliveryChannel(),
			providerName + "_cognito_identity_pool":                        resourceAwsCognitoIdentityPool(),
			providerName + "_cognito_identity_pool_roles_attachment":       resourceAwsCognitoIdentityPoolRolesAttachment(),
			providerName + "_cognito_identity_provider":                    resourceAwsCognitoIdentityProvider(),
			providerName + "_cognito_user_group":                           resourceAwsCognitoUserGroup(),
			providerName + "_cognito_user_pool":                            resourceAwsCognitoUserPool(),
			providerName + "_cognito_user_pool_client":                     resourceAwsCognitoUserPoolClient(),
			providerName + "_cognito_user_pool_domain":                     resourceAwsCognitoUserPoolDomain(),
			providerName + "_cloudhsm_v2_cluster":                          resourceAwsCloudHsm2Cluster(),
			providerName + "_cloudhsm_v2_hsm":                              resourceAwsCloudHsm2Hsm(),
			providerName + "_cognito_resource_server":                      resourceAwsCognitoResourceServer(),
			providerName + "_cloudwatch_metric_alarm":                      resourceAwsCloudWatchMetricAlarm(),
			providerName + "_cloudwatch_dashboard":                         resourceAwsCloudWatchDashboard(),
			providerName + "_codedeploy_app":                               resourceAwsCodeDeployApp(),
			providerName + "_codedeploy_deployment_config":                 resourceAwsCodeDeployDeploymentConfig(),
			providerName + "_codedeploy_deployment_group":                  resourceAwsCodeDeployDeploymentGroup(),
			providerName + "_codecommit_repository":                        resourceAwsCodeCommitRepository(),
			providerName + "_codecommit_trigger":                           resourceAwsCodeCommitTrigger(),
			providerName + "_codebuild_project":                            resourceAwsCodeBuildProject(),
			providerName + "_codebuild_webhook":                            resourceAwsCodeBuildWebhook(),
			providerName + "_codepipeline":                                 resourceAwsCodePipeline(),
			providerName + "_codepipeline_webhook":                         resourceAwsCodePipelineWebhook(),
			providerName + "_customer_gateway":                             resourceAwsCustomerGateway(),
			providerName + "_datasync_agent":                               resourceAwsDataSyncAgent(),
			providerName + "_datasync_location_efs":                        resourceAwsDataSyncLocationEfs(),
			providerName + "_datasync_location_nfs":                        resourceAwsDataSyncLocationNfs(),
			providerName + "_datasync_location_s3":                         resourceAwsDataSyncLocationS3(),
			providerName + "_datasync_task":                                resourceAwsDataSyncTask(),
			providerName + "_dax_cluster":                                  resourceAwsDaxCluster(),
			providerName + "_dax_parameter_group":                          resourceAwsDaxParameterGroup(),
			providerName + "_dax_subnet_group":                             resourceAwsDaxSubnetGroup(),
			providerName + "_db_cluster_snapshot":                          resourceAwsDbClusterSnapshot(),
			providerName + "_db_event_subscription":                        resourceAwsDbEventSubscription(),
			providerName + "_db_instance":                                  resourceAwsDbInstance(),
			providerName + "_db_option_group":                              resourceAwsDbOptionGroup(),
			providerName + "_db_parameter_group":                           resourceAwsDbParameterGroup(),
			providerName + "_db_security_group":                            resourceAwsDbSecurityGroup(),
			providerName + "_db_snapshot":                                  resourceAwsDbSnapshot(),
			providerName + "_db_subnet_group":                              resourceAwsDbSubnetGroup(),
			providerName + "_devicefarm_project":                           resourceAwsDevicefarmProject(),
			providerName + "_directory_service_directory":                  resourceAwsDirectoryServiceDirectory(),
			providerName + "_directory_service_conditional_forwarder":      resourceAwsDirectoryServiceConditionalForwarder(),
			providerName + "_dlm_lifecycle_policy":                         resourceAwsDlmLifecyclePolicy(),
			providerName + "_dms_certificate":                              resourceAwsDmsCertificate(),
			providerName + "_dms_endpoint":                                 resourceAwsDmsEndpoint(),
			providerName + "_dms_replication_instance":                     resourceAwsDmsReplicationInstance(),
			providerName + "_dms_replication_subnet_group":                 resourceAwsDmsReplicationSubnetGroup(),
			providerName + "_dms_replication_task":                         resourceAwsDmsReplicationTask(),
			providerName + "_dx_bgp_peer":                                  resourceAwsDxBgpPeer(),
			providerName + "_dx_connection":                                resourceAwsDxConnection(),
			providerName + "_dx_connection_association":                    resourceAwsDxConnectionAssociation(),
			providerName + "_dx_gateway":                                   resourceAwsDxGateway(),
			providerName + "_dx_gateway_association":                       resourceAwsDxGatewayAssociation(),
			providerName + "_dx_hosted_private_virtual_interface":          resourceAwsDxHostedPrivateVirtualInterface(),
			providerName + "_dx_hosted_private_virtual_interface_accepter": resourceAwsDxHostedPrivateVirtualInterfaceAccepter(),
			providerName + "_dx_hosted_public_virtual_interface":           resourceAwsDxHostedPublicVirtualInterface(),
			providerName + "_dx_hosted_public_virtual_interface_accepter":  resourceAwsDxHostedPublicVirtualInterfaceAccepter(),
			providerName + "_dx_lag":                                       resourceAwsDxLag(),
			providerName + "_dx_private_virtual_interface":                 resourceAwsDxPrivateVirtualInterface(),
			providerName + "_dx_public_virtual_interface":                  resourceAwsDxPublicVirtualInterface(),
			providerName + "_dynamodb_table":                               resourceAwsDynamoDbTable(),
			providerName + "_dynamodb_table_item":                          resourceAwsDynamoDbTableItem(),
			providerName + "_dynamodb_global_table":                        resourceAwsDynamoDbGlobalTable(),
			providerName + "_ebs_snapshot":                                 resourceAwsEbsSnapshot(),
			providerName + "_ebs_snapshot_copy":                            resourceAwsEbsSnapshotCopy(),
			providerName + "_ebs_volume":                                   resourceAwsEbsVolume(),
			providerName + "_ec2_capacity_reservation":                     resourceAwsEc2CapacityReservation(),
			providerName + "_ec2_fleet":                                    resourceAwsEc2Fleet(),
			providerName + "_ec2_transit_gateway":                          resourceAwsEc2TransitGateway(),
			providerName + "_ec2_transit_gateway_route":                    resourceAwsEc2TransitGatewayRoute(),
			providerName + "_ec2_transit_gateway_route_table":              resourceAwsEc2TransitGatewayRouteTable(),
			providerName + "_ec2_transit_gateway_route_table_association":  resourceAwsEc2TransitGatewayRouteTableAssociation(),
			providerName + "_ec2_transit_gateway_route_table_propagation":  resourceAwsEc2TransitGatewayRouteTablePropagation(),
			providerName + "_ec2_transit_gateway_vpc_attachment":           resourceAwsEc2TransitGatewayVpcAttachment(),
			providerName + "_ecr_lifecycle_policy":                         resourceAwsEcrLifecyclePolicy(),
			providerName + "_ecr_repository":                               resourceAwsEcrRepository(),
			providerName + "_ecr_repository_policy":                        resourceAwsEcrRepositoryPolicy(),
			providerName + "_ecs_cluster":                                  resourceAwsEcsCluster(),
			providerName + "_ecs_service":                                  resourceAwsEcsService(),
			providerName + "_ecs_task_definition":                          resourceAwsEcsTaskDefinition(),
			providerName + "_efs_file_system":                              resourceAwsEfsFileSystem(),
			providerName + "_efs_mount_target":                             resourceAwsEfsMountTarget(),
			providerName + "_egress_only_internet_gateway":                 resourceAwsEgressOnlyInternetGateway(),
			providerName + "_eip":                                          resourceAwsEip(),
			providerName + "_eip_association":                              resourceAwsEipAssociation(),
			providerName + "_eks_cluster":                                  resourceAwsEksCluster(),
			providerName + "_elasticache_cluster":                          resourceAwsElasticacheCluster(),
			providerName + "_elasticache_parameter_group":                  resourceAwsElasticacheParameterGroup(),
			providerName + "_elasticache_replication_group":                resourceAwsElasticacheReplicationGroup(),
			providerName + "_elasticache_security_group":                   resourceAwsElasticacheSecurityGroup(),
			providerName + "_elasticache_subnet_group":                     resourceAwsElasticacheSubnetGroup(),
			providerName + "_elastic_beanstalk_application":                resourceAwsElasticBeanstalkApplication(),
			providerName + "_elastic_beanstalk_application_version":        resourceAwsElasticBeanstalkApplicationVersion(),
			providerName + "_elastic_beanstalk_configuration_template":     resourceAwsElasticBeanstalkConfigurationTemplate(),
			providerName + "_elastic_beanstalk_environment":                resourceAwsElasticBeanstalkEnvironment(),
			providerName + "_elasticsearch_domain":                         resourceAwsElasticSearchDomain(),
			providerName + "_elasticsearch_domain_policy":                  resourceAwsElasticSearchDomainPolicy(),
			providerName + "_elastictranscoder_pipeline":                   resourceAwsElasticTranscoderPipeline(),
			providerName + "_elastictranscoder_preset":                     resourceAwsElasticTranscoderPreset(),
			providerName + "_elb":                                          resourceAwsElb(),
			providerName + "_elb_attachment":                               resourceAwsElbAttachment(),
			providerName + "_emr_cluster":                                  resourceAwsEMRCluster(),
			providerName + "_emr_instance_group":                           resourceAwsEMRInstanceGroup(),
			providerName + "_emr_security_configuration":                   resourceAwsEMRSecurityConfiguration(),
			providerName + "_flow_log":                                     resourceAwsFlowLog(),
			providerName + "_gamelift_alias":                               resourceAwsGameliftAlias(),
			providerName + "_gamelift_build":                               resourceAwsGameliftBuild(),
			providerName + "_gamelift_fleet":                               resourceAwsGameliftFleet(),
			providerName + "_gamelift_game_session_queue":                  resourceAwsGameliftGameSessionQueue(),
			providerName + "_glacier_vault":                                resourceAwsGlacierVault(),
			providerName + "_glacier_vault_lock":                           resourceAwsGlacierVaultLock(),
			providerName + "_glue_catalog_database":                        resourceAwsGlueCatalogDatabase(),
			providerName + "_glue_catalog_table":                           resourceAwsGlueCatalogTable(),
			providerName + "_glue_classifier":                              resourceAwsGlueClassifier(),
			providerName + "_glue_connection":                              resourceAwsGlueConnection(),
			providerName + "_glue_crawler":                                 resourceAwsGlueCrawler(),
			providerName + "_glue_job":                                     resourceAwsGlueJob(),
			providerName + "_glue_security_configuration":                  resourceAwsGlueSecurityConfiguration(),
			providerName + "_glue_trigger":                                 resourceAwsGlueTrigger(),
			providerName + "_guardduty_detector":                           resourceAwsGuardDutyDetector(),
			providerName + "_guardduty_ipset":                              resourceAwsGuardDutyIpset(),
			providerName + "_guardduty_member":                             resourceAwsGuardDutyMember(),
			providerName + "_guardduty_threatintelset":                     resourceAwsGuardDutyThreatintelset(),
			providerName + "_iam_access_key":                               resourceAwsIamAccessKey(),
			providerName + "_iam_account_alias":                            resourceAwsIamAccountAlias(),
			providerName + "_iam_account_password_policy":                  resourceAwsIamAccountPasswordPolicy(),
			providerName + "_iam_group_policy":                             resourceAwsIamGroupPolicy(),
			providerName + "_iam_group":                                    resourceAwsIamGroup(),
			providerName + "_iam_group_membership":                         resourceAwsIamGroupMembership(),
			providerName + "_iam_group_policy_attachment":                  resourceAwsIamGroupPolicyAttachment(),
			providerName + "_iam_instance_profile":                         resourceAwsIamInstanceProfile(),
			providerName + "_iam_openid_connect_provider":                  resourceAwsIamOpenIDConnectProvider(),
			providerName + "_iam_policy":                                   resourceAwsIamPolicy(),
			providerName + "_iam_policy_attachment":                        resourceAwsIamPolicyAttachment(),
			providerName + "_iam_role_policy_attachment":                   resourceAwsIamRolePolicyAttachment(),
			providerName + "_iam_role_policy":                              resourceAwsIamRolePolicy(),
			providerName + "_iam_role":                                     resourceAwsIamRole(),
			providerName + "_iam_saml_provider":                            resourceAwsIamSamlProvider(),
			providerName + "_iam_server_certificate":                       resourceAwsIAMServerCertificate(),
			providerName + "_iam_service_linked_role":                      resourceAwsIamServiceLinkedRole(),
			providerName + "_iam_user_group_membership":                    resourceAwsIamUserGroupMembership(),
			providerName + "_iam_user_policy_attachment":                   resourceAwsIamUserPolicyAttachment(),
			providerName + "_iam_user_policy":                              resourceAwsIamUserPolicy(),
			providerName + "_iam_user_ssh_key":                             resourceAwsIamUserSshKey(),
			providerName + "_iam_user":                                     resourceAwsIamUser(),
			providerName + "_iam_user_login_profile":                       resourceAwsIamUserLoginProfile(),
			providerName + "_inspector_assessment_target":                  resourceAWSInspectorAssessmentTarget(),
			providerName + "_inspector_assessment_template":                resourceAWSInspectorAssessmentTemplate(),
			providerName + "_inspector_resource_group":                     resourceAWSInspectorResourceGroup(),
			providerName + "_instance":                                     resourceAwsInstance(),
			providerName + "_internet_gateway":                             resourceAwsInternetGateway(),
			providerName + "_iot_certificate":                              resourceAwsIotCertificate(),
			providerName + "_iot_policy":                                   resourceAwsIotPolicy(),
			providerName + "_iot_policy_attachment":                        resourceAwsIotPolicyAttachment(),
			providerName + "_iot_thing":                                    resourceAwsIotThing(),
			providerName + "_iot_thing_principal_attachment":               resourceAwsIotThingPrincipalAttachment(),
			providerName + "_iot_thing_type":                               resourceAwsIotThingType(),
			providerName + "_iot_topic_rule":                               resourceAwsIotTopicRule(),
			providerName + "_key_pair":                                     resourceAwsKeyPair(),
			providerName + "_kinesis_firehose_delivery_stream":             resourceAwsKinesisFirehoseDeliveryStream(),
			providerName + "_kinesis_stream":                               resourceAwsKinesisStream(),
			providerName + "_kinesis_analytics_application":                resourceAwsKinesisAnalyticsApplication(),
			providerName + "_kms_alias":                                    resourceAwsKmsAlias(),
			providerName + "_kms_grant":                                    resourceAwsKmsGrant(),
			providerName + "_kms_key":                                      resourceAwsKmsKey(),
			providerName + "_lambda_function":                              resourceAwsLambdaFunction(),
			providerName + "_lambda_event_source_mapping":                  resourceAwsLambdaEventSourceMapping(),
			providerName + "_lambda_alias":                                 resourceAwsLambdaAlias(),
			providerName + "_lambda_permission":                            resourceAwsLambdaPermission(),
			providerName + "_launch_configuration":                         resourceAwsLaunchConfiguration(),
			providerName + "_launch_template":                              resourceAwsLaunchTemplate(),
			providerName + "_lightsail_domain":                             resourceAwsLightsailDomain(),
			providerName + "_lightsail_instance":                           resourceAwsLightsailInstance(),
			providerName + "_lightsail_key_pair":                           resourceAwsLightsailKeyPair(),
			providerName + "_lightsail_static_ip":                          resourceAwsLightsailStaticIp(),
			providerName + "_lightsail_static_ip_attachment":               resourceAwsLightsailStaticIpAttachment(),
			providerName + "_lb_cookie_stickiness_policy":                  resourceAwsLBCookieStickinessPolicy(),
			providerName + "_load_balancer_policy":                         resourceAwsLoadBalancerPolicy(),
			providerName + "_load_balancer_backend_server_policy":          resourceAwsLoadBalancerBackendServerPolicies(),
			providerName + "_load_balancer_listener_policy":                resourceAwsLoadBalancerListenerPolicies(),
			providerName + "_lb_ssl_negotiation_policy":                    resourceAwsLBSSLNegotiationPolicy(),
			providerName + "_macie_member_account_association":             resourceAwsMacieMemberAccountAssociation(),
			providerName + "_macie_s3_bucket_association":                  resourceAwsMacieS3BucketAssociation(),
			providerName + "_main_route_table_association":                 resourceAwsMainRouteTableAssociation(),
			providerName + "_mq_broker":                                    resourceAwsMqBroker(),
			providerName + "_mq_configuration":                             resourceAwsMqConfiguration(),
			providerName + "_media_store_container":                        resourceAwsMediaStoreContainer(),
			providerName + "_media_store_container_policy":                 resourceAwsMediaStoreContainerPolicy(),
			providerName + "_nat_gateway":                                  resourceAwsNatGateway(),
			providerName + "_network_acl":                                  resourceAwsNetworkAcl(),
			providerName + "_default_network_acl":                          resourceAwsDefaultNetworkAcl(),
			providerName + "_neptune_cluster":                              resourceAwsNeptuneCluster(),
			providerName + "_neptune_cluster_instance":                     resourceAwsNeptuneClusterInstance(),
			providerName + "_neptune_cluster_parameter_group":              resourceAwsNeptuneClusterParameterGroup(),
			providerName + "_neptune_cluster_snapshot":                     resourceAwsNeptuneClusterSnapshot(),
			providerName + "_neptune_event_subscription":                   resourceAwsNeptuneEventSubscription(),
			providerName + "_neptune_parameter_group":                      resourceAwsNeptuneParameterGroup(),
			providerName + "_neptune_subnet_group":                         resourceAwsNeptuneSubnetGroup(),
			providerName + "_network_acl_rule":                             resourceAwsNetworkAclRule(),
			providerName + "_network_interface":                            resourceAwsNetworkInterface(),
			providerName + "_network_interface_attachment":                 resourceAwsNetworkInterfaceAttachment(),
			providerName + "_opsworks_application":                         resourceAwsOpsworksApplication(),
			providerName + "_opsworks_stack":                               resourceAwsOpsworksStack(),
			providerName + "_opsworks_java_app_layer":                      resourceAwsOpsworksJavaAppLayer(),
			providerName + "_opsworks_haproxy_layer":                       resourceAwsOpsworksHaproxyLayer(),
			providerName + "_opsworks_static_web_layer":                    resourceAwsOpsworksStaticWebLayer(),
			providerName + "_opsworks_php_app_layer":                       resourceAwsOpsworksPhpAppLayer(),
			providerName + "_opsworks_rails_app_layer":                     resourceAwsOpsworksRailsAppLayer(),
			providerName + "_opsworks_nodejs_app_layer":                    resourceAwsOpsworksNodejsAppLayer(),
			providerName + "_opsworks_memcached_layer":                     resourceAwsOpsworksMemcachedLayer(),
			providerName + "_opsworks_mysql_layer":                         resourceAwsOpsworksMysqlLayer(),
			providerName + "_opsworks_ganglia_layer":                       resourceAwsOpsworksGangliaLayer(),
			providerName + "_opsworks_custom_layer":                        resourceAwsOpsworksCustomLayer(),
			providerName + "_opsworks_instance":                            resourceAwsOpsworksInstance(),
			providerName + "_opsworks_user_profile":                        resourceAwsOpsworksUserProfile(),
			providerName + "_opsworks_permission":                          resourceAwsOpsworksPermission(),
			providerName + "_opsworks_rds_db_instance":                     resourceAwsOpsworksRdsDbInstance(),
			providerName + "_organizations_organization":                   resourceAwsOrganizationsOrganization(),
			providerName + "_organizations_account":                        resourceAwsOrganizationsAccount(),
			providerName + "_organizations_policy":                         resourceAwsOrganizationsPolicy(),
			providerName + "_organizations_policy_attachment":              resourceAwsOrganizationsPolicyAttachment(),
			providerName + "_placement_group":                              resourceAwsPlacementGroup(),
			providerName + "_proxy_protocol_policy":                        resourceAwsProxyProtocolPolicy(),
			providerName + "_rds_cluster":                                  resourceAwsRDSCluster(),
			providerName + "_rds_cluster_instance":                         resourceAwsRDSClusterInstance(),
			providerName + "_rds_cluster_parameter_group":                  resourceAwsRDSClusterParameterGroup(),
			providerName + "_redshift_cluster":                             resourceAwsRedshiftCluster(),
			providerName + "_redshift_security_group":                      resourceAwsRedshiftSecurityGroup(),
			providerName + "_redshift_parameter_group":                     resourceAwsRedshiftParameterGroup(),
			providerName + "_redshift_subnet_group":                        resourceAwsRedshiftSubnetGroup(),
			providerName + "_redshift_snapshot_copy_grant":                 resourceAwsRedshiftSnapshotCopyGrant(),
			providerName + "_redshift_event_subscription":                  resourceAwsRedshiftEventSubscription(),
			providerName + "_route53_delegation_set":                       resourceAwsRoute53DelegationSet(),
			providerName + "_route53_query_log":                            resourceAwsRoute53QueryLog(),
			providerName + "_route53_record":                               resourceAwsRoute53Record(),
			providerName + "_route53_zone_association":                     resourceAwsRoute53ZoneAssociation(),
			providerName + "_route53_zone":                                 resourceAwsRoute53Zone(),
			providerName + "_route53_health_check":                         resourceAwsRoute53HealthCheck(),
			providerName + "_route":                                        resourceAwsRoute(),
			providerName + "_route_table":                                  resourceAwsRouteTable(),
			providerName + "_default_route_table":                          resourceAwsDefaultRouteTable(),
			providerName + "_route_table_association":                      resourceAwsRouteTableAssociation(),
			providerName + "_secretsmanager_secret":                        resourceAwsSecretsManagerSecret(),
			providerName + "_secretsmanager_secret_version":                resourceAwsSecretsManagerSecretVersion(),
			providerName + "_ses_active_receipt_rule_set":                  resourceAwsSesActiveReceiptRuleSet(),
			providerName + "_ses_domain_identity":                          resourceAwsSesDomainIdentity(),
			providerName + "_ses_domain_identity_verification":             resourceAwsSesDomainIdentityVerification(),
			providerName + "_ses_domain_dkim":                              resourceAwsSesDomainDkim(),
			providerName + "_ses_domain_mail_from":                         resourceAwsSesDomainMailFrom(),
			providerName + "_ses_receipt_filter":                           resourceAwsSesReceiptFilter(),
			providerName + "_ses_receipt_rule":                             resourceAwsSesReceiptRule(),
			providerName + "_ses_receipt_rule_set":                         resourceAwsSesReceiptRuleSet(),
			providerName + "_ses_configuration_set":                        resourceAwsSesConfigurationSet(),
			providerName + "_ses_event_destination":                        resourceAwsSesEventDestination(),
			providerName + "_ses_identity_notification_topic":              resourceAwsSesNotificationTopic(),
			providerName + "_ses_template":                                 resourceAwsSesTemplate(),
			providerName + "_s3_bucket":                                    resourceAwsS3Bucket(),
			providerName + "_s3_bucket_policy":                             resourceAwsS3BucketPolicy(),
			providerName + "_s3_bucket_object":                             resourceAwsS3BucketObject(),
			providerName + "_s3_bucket_notification":                       resourceAwsS3BucketNotification(),
			providerName + "_s3_bucket_metric":                             resourceAwsS3BucketMetric(),
			providerName + "_s3_bucket_inventory":                          resourceAwsS3BucketInventory(),
			providerName + "_security_group":                               resourceAwsSecurityGroup(),
			providerName + "_network_interface_sg_attachment":              resourceAwsNetworkInterfaceSGAttachment(),
			providerName + "_default_security_group":                       resourceAwsDefaultSecurityGroup(),
			providerName + "_security_group_rule":                          resourceAwsSecurityGroupRule(),
			providerName + "_servicecatalog_portfolio":                     resourceAwsServiceCatalogPortfolio(),
			providerName + "_service_discovery_private_dns_namespace":      resourceAwsServiceDiscoveryPrivateDnsNamespace(),
			providerName + "_service_discovery_public_dns_namespace":       resourceAwsServiceDiscoveryPublicDnsNamespace(),
			providerName + "_service_discovery_service":                    resourceAwsServiceDiscoveryService(),
			providerName + "_simpledb_domain":                              resourceAwsSimpleDBDomain(),
			providerName + "_ssm_activation":                               resourceAwsSsmActivation(),
			providerName + "_ssm_association":                              resourceAwsSsmAssociation(),
			providerName + "_ssm_document":                                 resourceAwsSsmDocument(),
			providerName + "_ssm_maintenance_window":                       resourceAwsSsmMaintenanceWindow(),
			providerName + "_ssm_maintenance_window_target":                resourceAwsSsmMaintenanceWindowTarget(),
			providerName + "_ssm_maintenance_window_task":                  resourceAwsSsmMaintenanceWindowTask(),
			providerName + "_ssm_patch_baseline":                           resourceAwsSsmPatchBaseline(),
			providerName + "_ssm_patch_group":                              resourceAwsSsmPatchGroup(),
			providerName + "_ssm_parameter":                                resourceAwsSsmParameter(),
			providerName + "_ssm_resource_data_sync":                       resourceAwsSsmResourceDataSync(),
			providerName + "_storagegateway_cache":                         resourceAwsStorageGatewayCache(),
			providerName + "_storagegateway_cached_iscsi_volume":           resourceAwsStorageGatewayCachedIscsiVolume(),
			providerName + "_storagegateway_gateway":                       resourceAwsStorageGatewayGateway(),
			providerName + "_storagegateway_nfs_file_share":                resourceAwsStorageGatewayNfsFileShare(),
			providerName + "_storagegateway_smb_file_share":                resourceAwsStorageGatewaySmbFileShare(),
			providerName + "_storagegateway_upload_buffer":                 resourceAwsStorageGatewayUploadBuffer(),
			providerName + "_storagegateway_working_storage":               resourceAwsStorageGatewayWorkingStorage(),
			providerName + "_spot_datafeed_subscription":                   resourceAwsSpotDataFeedSubscription(),
			providerName + "_spot_instance_request":                        resourceAwsSpotInstanceRequest(),
			providerName + "_spot_fleet_request":                           resourceAwsSpotFleetRequest(),
			providerName + "_sqs_queue":                                    resourceAwsSqsQueue(),
			providerName + "_sqs_queue_policy":                             resourceAwsSqsQueuePolicy(),
			providerName + "_snapshot_create_volume_permission":            resourceAwsSnapshotCreateVolumePermission(),
			providerName + "_sns_platform_application":                     resourceAwsSnsPlatformApplication(),
			providerName + "_sns_sms_preferences":                          resourceAwsSnsSmsPreferences(),
			providerName + "_sns_topic":                                    resourceAwsSnsTopic(),
			providerName + "_sns_topic_policy":                             resourceAwsSnsTopicPolicy(),
			providerName + "_sns_topic_subscription":                       resourceAwsSnsTopicSubscription(),
			providerName + "_sfn_activity":                                 resourceAwsSfnActivity(),
			providerName + "_sfn_state_machine":                            resourceAwsSfnStateMachine(),
			providerName + "_default_subnet":                               resourceAwsDefaultSubnet(),
			providerName + "_subnet":                                       resourceAwsSubnet(),
			providerName + "_swf_domain":                                   resourceAwsSwfDomain(),
			providerName + "_volume_attachment":                            resourceAwsVolumeAttachment(),
			providerName + "_vpc_dhcp_options_association":                 resourceAwsVpcDhcpOptionsAssociation(),
			providerName + "_default_vpc_dhcp_options":                     resourceAwsDefaultVpcDhcpOptions(),
			providerName + "_vpc_dhcp_options":                             resourceAwsVpcDhcpOptions(),
			providerName + "_vpc_peering_connection":                       resourceAwsVpcPeeringConnection(),
			providerName + "_vpc_peering_connection_accepter":              resourceAwsVpcPeeringConnectionAccepter(),
			providerName + "_vpc_peering_connection_options":               resourceAwsVpcPeeringConnectionOptions(),
			providerName + "_default_vpc":                                  resourceAwsDefaultVpc(),
			providerName + "_vpc":                                          resourceAwsVpc(),
			providerName + "_vpc_endpoint":                                 resourceAwsVpcEndpoint(),
			providerName + "_vpc_endpoint_connection_notification":         resourceAwsVpcEndpointConnectionNotification(),
			providerName + "_vpc_endpoint_route_table_association":         resourceAwsVpcEndpointRouteTableAssociation(),
			providerName + "_vpc_endpoint_subnet_association":              resourceAwsVpcEndpointSubnetAssociation(),
			providerName + "_vpc_endpoint_service":                         resourceAwsVpcEndpointService(),
			providerName + "_vpc_endpoint_service_allowed_principal":       resourceAwsVpcEndpointServiceAllowedPrincipal(),
			providerName + "_vpc_ipv4_cidr_block_association":              resourceAwsVpcIpv4CidrBlockAssociation(),
			providerName + "_vpn_connection":                               resourceAwsVpnConnection(),
			providerName + "_vpn_connection_route":                         resourceAwsVpnConnectionRoute(),
			providerName + "_vpn_gateway":                                  resourceAwsVpnGateway(),
			providerName + "_vpn_gateway_attachment":                       resourceAwsVpnGatewayAttachment(),
			providerName + "_vpn_gateway_route_propagation":                resourceAwsVpnGatewayRoutePropagation(),
			providerName + "_waf_byte_match_set":                           resourceAwsWafByteMatchSet(),
			providerName + "_waf_ipset":                                    resourceAwsWafIPSet(),
			providerName + "_waf_rate_based_rule":                          resourceAwsWafRateBasedRule(),
			providerName + "_waf_regex_match_set":                          resourceAwsWafRegexMatchSet(),
			providerName + "_waf_regex_pattern_set":                        resourceAwsWafRegexPatternSet(),
			providerName + "_waf_rule":                                     resourceAwsWafRule(),
			providerName + "_waf_rule_group":                               resourceAwsWafRuleGroup(),
			providerName + "_waf_size_constraint_set":                      resourceAwsWafSizeConstraintSet(),
			providerName + "_waf_web_acl":                                  resourceAwsWafWebAcl(),
			providerName + "_waf_xss_match_set":                            resourceAwsWafXssMatchSet(),
			providerName + "_waf_sql_injection_match_set":                  resourceAwsWafSqlInjectionMatchSet(),
			providerName + "_waf_geo_match_set":                            resourceAwsWafGeoMatchSet(),
			providerName + "_wafregional_byte_match_set":                   resourceAwsWafRegionalByteMatchSet(),
			providerName + "_wafregional_geo_match_set":                    resourceAwsWafRegionalGeoMatchSet(),
			providerName + "_wafregional_ipset":                            resourceAwsWafRegionalIPSet(),
			providerName + "_wafregional_rate_based_rule":                  resourceAwsWafRegionalRateBasedRule(),
			providerName + "_wafregional_regex_match_set":                  resourceAwsWafRegionalRegexMatchSet(),
			providerName + "_wafregional_regex_pattern_set":                resourceAwsWafRegionalRegexPatternSet(),
			providerName + "_wafregional_rule":                             resourceAwsWafRegionalRule(),
			providerName + "_wafregional_rule_group":                       resourceAwsWafRegionalRuleGroup(),
			providerName + "_wafregional_size_constraint_set":              resourceAwsWafRegionalSizeConstraintSet(),
			providerName + "_wafregional_sql_injection_match_set":          resourceAwsWafRegionalSqlInjectionMatchSet(),
			providerName + "_wafregional_xss_match_set":                    resourceAwsWafRegionalXssMatchSet(),
			providerName + "_wafregional_web_acl":                          resourceAwsWafRegionalWebAcl(),
			providerName + "_wafregional_web_acl_association":              resourceAwsWafRegionalWebAclAssociation(),
			providerName + "_batch_compute_environment":                    resourceAwsBatchComputeEnvironment(),
			providerName + "_batch_job_definition":                         resourceAwsBatchJobDefinition(),
			providerName + "_batch_job_queue":                              resourceAwsBatchJobQueue(),
			providerName + "_pinpoint_app":                                 resourceAwsPinpointApp(),
			providerName + "_pinpoint_adm_channel":                         resourceAwsPinpointADMChannel(),
			providerName + "_pinpoint_apns_channel":                        resourceAwsPinpointAPNSChannel(),
			providerName + "_pinpoint_apns_sandbox_channel":                resourceAwsPinpointAPNSSandboxChannel(),
			providerName + "_pinpoint_apns_voip_channel":                   resourceAwsPinpointAPNSVoipChannel(),
			providerName + "_pinpoint_apns_voip_sandbox_channel":           resourceAwsPinpointAPNSVoipSandboxChannel(),
			providerName + "_pinpoint_baidu_channel":                       resourceAwsPinpointBaiduChannel(),
			providerName + "_pinpoint_email_channel":                       resourceAwsPinpointEmailChannel(),
			providerName + "_pinpoint_event_stream":                        resourceAwsPinpointEventStream(),
			providerName + "_pinpoint_gcm_channel":                         resourceAwsPinpointGCMChannel(),
			providerName + "_pinpoint_sms_channel":                         resourceAwsPinpointSMSChannel(),

			// ALBs are actually LBs because they can be type `network` or `application`
			// To avoid regressions, we will add a new resource for each and they both point
			// back to the old ALB version. IF the Terraform supported aliases for resources
			// this would be a whole lot simpler
			providerName + "_alb":                         resourceAwsLb(),
			providerName + "_lb":                          resourceAwsLb(),
			providerName + "_alb_listener":                resourceAwsLbListener(),
			providerName + "_lb_listener":                 resourceAwsLbListener(),
			providerName + "_alb_listener_certificate":    resourceAwsLbListenerCertificate(),
			providerName + "_lb_listener_certificate":     resourceAwsLbListenerCertificate(),
			providerName + "_alb_listener_rule":           resourceAwsLbbListenerRule(),
			providerName + "_lb_listener_rule":            resourceAwsLbbListenerRule(),
			providerName + "_alb_target_group":            resourceAwsLbTargetGroup(),
			providerName + "_lb_target_group":             resourceAwsLbTargetGroup(),
			providerName + "_alb_target_group_attachment": resourceAwsLbTargetGroupAttachment(),
			providerName + "_lb_target_group_attachment":  resourceAwsLbTargetGroupAttachment(),
		},
		ConfigureFunc: providerConfigure,
	}
}

var descriptions map[string]string

func init() {
	descriptions = map[string]string{
		"region": "The region where AWS operations will take place. Examples\n" +
			"are us-east-1, us-west-2, etc.",

		"access_key": "The access key for API operations. You can retrieve this\n" +
			"from the 'Security & Credentials' section of the AWS console.",

		"secret_key": "The secret key for API operations. You can retrieve this\n" +
			"from the 'Security & Credentials' section of the AWS console.",

		"profile": "The profile for API operations. If not set, the default profile\n" +
			"created with `aws configure` will be used.",

		"shared_credentials_file": "The path to the shared credentials file. If not set\n" +
			"this defaults to ~/.aws/credentials.",

		"token": "session token. A session token is only required if you are\n" +
			"using temporary security credentials.",

		"max_retries": "The maximum number of times an AWS API request is\n" +
			"being executed. If the API request still fails, an error is\n" +
			"thrown.",

		"apigateway_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"cloudformation_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"cloudwatch_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"cloudwatchevents_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"cloudwatchlogs_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"devicefarm_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"dynamodb_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n" +
			"It's typically used to connect to dynamodb-local.",

		"kinesis_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n" +
			"It's typically used to connect to kinesalite.",

		"kinesis_analytics_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"kms_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"iam_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"lambda_endpoint": "Use this to override the default endpoint URL constructed from the `region`\n",

		"ec2_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"autoscaling_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"efs_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"elb_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"es_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"rds_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"s3_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"sns_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"sqs_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"ssm_endpoint": "Use this to override the default endpoint URL constructed from the `region`.\n",

		"insecure": "Explicitly allow the provider to perform \"insecure\" SSL requests. If omitted," +
			"default value is `false`",

		"skip_credentials_validation": "Skip the credentials validation via STS API. " +
			"Used for AWS API implementations that do not have STS available/implemented.",

		"skip_get_ec2_platforms": "Skip getting the supported EC2 platforms. " +
			"Used by users that don't have ec2:DescribeAccountAttributes permissions.",

		"skip_region_validation": "Skip static validation of region name. " +
			"Used by users of alternative AWS-like APIs or users w/ access to regions that are not public (yet).",

		"skip_requesting_account_id": "Skip requesting the account ID. " +
			"Used for AWS API implementations that do not have IAM/STS API and/or metadata API.",

		"skip_medatadata_api_check": "Skip the AWS Metadata API check. " +
			"Used for AWS API implementations that do not have a metadata api endpoint.",

		"s3_force_path_style": "Set this to true to force the request to use path-style addressing,\n" +
			"i.e., http://s3.amazonaws.com/BUCKET/KEY. By default, the S3 client will\n" +
			"use virtual hosted bucket addressing when possible\n" +
			"(http://BUCKET.s3.amazonaws.com/KEY). Specific to the Amazon S3 service.",

		"assume_role_role_arn": "The ARN of an IAM role to assume prior to making API calls.",

		"assume_role_session_name": "The session name to use when assuming the role. If omitted," +
			" no session name is passed to the AssumeRole call.",

		"assume_role_external_id": "The external ID to use when assuming the role. If omitted," +
			" no external ID is passed to the AssumeRole call.",

		"assume_role_policy": "The permissions applied when assuming a role. You cannot use," +
			" this policy to grant further permissions that are in excess to those of the, " +
			" role that is being assumed.",
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		AccessKey:               d.Get("access_key").(string),
		SecretKey:               d.Get("secret_key").(string),
		Profile:                 d.Get("profile").(string),
		Token:                   d.Get("token").(string),
		Region:                  d.Get("region").(string),
		MaxRetries:              d.Get("max_retries").(int),
		Insecure:                d.Get("insecure").(bool),
		SkipCredsValidation:     d.Get("skip_credentials_validation").(bool),
		SkipGetEC2Platforms:     d.Get("skip_get_ec2_platforms").(bool),
		SkipRegionValidation:    d.Get("skip_region_validation").(bool),
		SkipRequestingAccountId: d.Get("skip_requesting_account_id").(bool),
		SkipMetadataApiCheck:    d.Get("skip_metadata_api_check").(bool),
		S3ForcePathStyle:        d.Get("s3_force_path_style").(bool),
	}

	// Set CredsFilename, expanding home directory
	credsPath, err := homedir.Expand(d.Get("shared_credentials_file").(string))
	if err != nil {
		return nil, err
	}
	config.CredsFilename = credsPath

	assumeRoleList := d.Get("assume_role").(*schema.Set).List()
	if len(assumeRoleList) == 1 {
		assumeRole := assumeRoleList[0].(map[string]interface{})
		config.AssumeRoleARN = assumeRole["role_arn"].(string)
		config.AssumeRoleSessionName = assumeRole["session_name"].(string)
		config.AssumeRoleExternalID = assumeRole["external_id"].(string)

		if v := assumeRole["policy"].(string); v != "" {
			config.AssumeRolePolicy = v
		}

		log.Printf("[INFO] assume_role configuration set: (ARN: %q, SessionID: %q, ExternalID: %q, Policy: %q)",
			config.AssumeRoleARN, config.AssumeRoleSessionName, config.AssumeRoleExternalID, config.AssumeRolePolicy)
	} else {
		log.Printf("[INFO] No assume_role block read from configuration")
	}

	endpointsSet := d.Get("endpoints").(*schema.Set)

	for _, endpointsSetI := range endpointsSet.List() {
		endpoints := endpointsSetI.(map[string]interface{})
		config.AcmEndpoint = endpoints["acm"].(string)
		config.ApigatewayEndpoint = endpoints["apigateway"].(string)
		config.CloudFormationEndpoint = endpoints["cloudformation"].(string)
		config.CloudWatchEndpoint = endpoints["cloudwatch"].(string)
		config.CloudWatchEventsEndpoint = endpoints["cloudwatchevents"].(string)
		config.CloudWatchLogsEndpoint = endpoints["cloudwatchlogs"].(string)
		config.DeviceFarmEndpoint = endpoints["devicefarm"].(string)
		config.DynamoDBEndpoint = endpoints["dynamodb"].(string)
		config.Ec2Endpoint = endpoints["ec2"].(string)
		config.AutoscalingEndpoint = endpoints["autoscaling"].(string)
		config.EcrEndpoint = endpoints["ecr"].(string)
		config.EcsEndpoint = endpoints["ecs"].(string)
		config.EfsEndpoint = endpoints["efs"].(string)
		config.ElbEndpoint = endpoints["elb"].(string)
		config.EsEndpoint = endpoints["es"].(string)
		config.IamEndpoint = endpoints["iam"].(string)
		config.KinesisEndpoint = endpoints["kinesis"].(string)
		config.KinesisAnalyticsEndpoint = endpoints["kinesis_analytics"].(string)
		config.KmsEndpoint = endpoints["kms"].(string)
		config.LambdaEndpoint = endpoints["lambda"].(string)
		config.R53Endpoint = endpoints["r53"].(string)
		config.RdsEndpoint = endpoints["rds"].(string)
		config.S3Endpoint = endpoints["s3"].(string)
		config.SnsEndpoint = endpoints["sns"].(string)
		config.SqsEndpoint = endpoints["sqs"].(string)
		config.StsEndpoint = endpoints["sts"].(string)
		config.SsmEndpoint = endpoints["ssm"].(string)
	}

	if v, ok := d.GetOk("allowed_account_ids"); ok {
		config.AllowedAccountIds = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("forbidden_account_ids"); ok {
		config.ForbiddenAccountIds = v.(*schema.Set).List()
	}

	return config.Client()
}

// This is a global MutexKV for use within this plugin.
var awsMutexKV = mutexkv.NewMutexKV()

func assumeRoleSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"role_arn": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: descriptions["assume_role_role_arn"],
				},

				"session_name": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: descriptions["assume_role_session_name"],
				},

				"external_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: descriptions["assume_role_external_id"],
				},

				"policy": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: descriptions["assume_role_policy"],
				},
			},
		},
	}
}

func endpointsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"acm": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["acm_endpoint"],
				},
				"apigateway": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["apigateway_endpoint"],
				},
				"cloudwatch": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["cloudwatch_endpoint"],
				},
				"cloudwatchevents": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["cloudwatchevents_endpoint"],
				},
				"cloudwatchlogs": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["cloudwatchlogs_endpoint"],
				},
				"cloudformation": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["cloudformation_endpoint"],
				},
				"devicefarm": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["devicefarm_endpoint"],
				},
				"dynamodb": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["dynamodb_endpoint"],
				},
				"iam": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["iam_endpoint"],
				},

				"ec2": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["ec2_endpoint"],
				},

				"autoscaling": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["autoscaling_endpoint"],
				},

				"ecr": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["ecr_endpoint"],
				},

				"ecs": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["ecs_endpoint"],
				},

				"efs": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["efs_endpoint"],
				},

				"elb": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["elb_endpoint"],
				},
				"es": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["es_endpoint"],
				},
				"kinesis": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["kinesis_endpoint"],
				},
				"kinesis_analytics": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["kinesis_analytics_endpoint"],
				},
				"kms": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["kms_endpoint"],
				},
				"lambda": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["lambda_endpoint"],
				},
				"r53": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["r53_endpoint"],
				},
				"rds": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["rds_endpoint"],
				},
				"s3": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["s3_endpoint"],
				},
				"sns": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["sns_endpoint"],
				},
				"sqs": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["sqs_endpoint"],
				},
				"sts": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["sts_endpoint"],
				},
				"ssm": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["ssm_endpoint"],
				},
			},
		},
		Set: endpointsToHash,
	}
}

func endpointsToHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["apigateway"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["cloudwatch"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["cloudwatchevents"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["cloudwatchlogs"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["cloudformation"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["devicefarm"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["dynamodb"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["iam"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["ec2"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["autoscaling"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["efs"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["elb"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["kinesis"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["kms"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["lambda"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["rds"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["s3"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["sns"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["sqs"].(string)))

	return hashcode.String(buf.String())
}

import logging
import time
import sys
from io import StringIO
import traceback
import json
from random import randint

from azure.identity import AzureCliCredential, DefaultAzureCredential, EnvironmentCredential, ClientSecretCredential, ChainedTokenCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerinstance.models import (ContainerGroup,
                                                 Container,
                                                 ContainerGroupNetworkProtocol,
                                                 ContainerGroupRestartPolicy,
                                                 ContainerPort,
                                                 EnvironmentVariable,
                                                 IpAddress,
                                                 Port,
                                                 ResourceRequests,
                                                 ResourceRequirements,
                                                 OperatingSystemTypes,
                                                 ImageRegistryCredential)
import azure.functions as func


# fix over logging issue
try:
    # set the default SDK logging level
    azure_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    azure_logger.setLevel(logging.WARNING)
except:
    pass


SAMPLE_REQUEST_BODY = {
    'subscription_id': 'azure subscription id (NOT the name)',
    'resource_group': "name of resource group to create the container in (ie: 'xdtmw2dihemgrego01')",
    'image_name': "full container image name in Azure Container Registry (ACR) (ie: 'emgvectorclexport.azurecr.io/clexporter:latest')",
    'container_registry_credentials': {
        'server': "azure container registry server url (ie: 'emgvectorclexport.azurecr.io')",
        'username': "user name for the container registry",
        'password': "password for the container registry",
    },
    'sas_key': "azure storage account SAS key to access input/output clf files",
    'input_path': "azure blob storage path to input CLF file. This must be path to a single CLF file or a directory containing multiple CLF files ONLY",
    'output_path': "azure blob storage path to output converted CSV files. existing files are overwritten",
    'analysis_package_path': "azure blob storage path to analysis package folder. this must be a folder path which contains analysis packages",
    'rename_file_path': "azure blob storage path to rename file .bat script to use",

    'container_name': "(optional) unique container instance group name (ie: 'clexport-inst-0001'). a random container name is generated if omitted",
    'service_account_credentials': {
        'tenant_id': "(optional) service account tenant id",
        'client_id': "(optional) service account client id",
        'client_secret': "(optional) service account tenant secret",
    },
    'cpu': "(optional) amount of cpu in decimal (default: 2)",
    'mem': "(optional) amount of memory in GB (default: 4.0)",
    'wait': "(optional) wait for container to finish running. the function timeouts if you set this to true (default: false)",
    'delete': "(optional) delete the container after it's finished. must use with wait=true. don't use this (default: false)",
}


def create_container_instance(
    client: ContainerInstanceManagementClient,
    container_name: str, 
    resource_group: ResourceGroup,
    image_name: str,
    container_registry_credentials: dict,
    command_line: list = None,
    environment_variables: dict = None,
    cpu: float = 2.0,
    mem: float = 4.0,
    wait: bool = True,
    ):
    """
    Creates a container group with a single task-based container who's
    restart policy is 'Never'. If specified, the container runs a custom
    command line at startup.
    """
    # Configure some environment variables in the container which the
    # wordcount.py or other script can read to modify its behavior.
    if environment_variables is not None:
        env_vars = [EnvironmentVariable(name=k, value=v) for k, v in environment_variables.items()]
    else: 
        env_vars = None
    registry_credentials = ImageRegistryCredential(**container_registry_credentials)
    logging.info(f"Creating container group '{container_name}'")
    logging.info(f"Container command: {command_line}")
    for k, v in environment_variables.items():
        logging.info(f"Container ENV  {k}='{v}'")

    # Configure the container
    container_resource_requests = ResourceRequests(memory_in_gb=mem, cpu=cpu)
    container_resource_requirements = ResourceRequirements(requests=container_resource_requests)
    container = Container(name=container_name,
                          image=image_name,
                          resources=container_resource_requirements,
                          environment_variables=env_vars,
                          command=command_line)

    # Configure the container group
    group = ContainerGroup(location=resource_group.location,
                           containers=[container],
                           os_type=OperatingSystemTypes.WINDOWS,
                           image_registry_credentials=[registry_credentials],
                           restart_policy=ContainerGroupRestartPolicy.never)
    
    result = client.container_groups.begin_create_or_update(
        resource_group.name,
        container_name,
        group
        )

    # Wait for the container create operation to complete. The operation is
    # "done" when the container group provisioning state is one of:
    # Succeeded, Canceled, Failed
    if wait:
        while result.done() is False:
            sys.stdout.write('.')
            time.sleep(5)
        print("\n")
        # Get the provisioning state of the container group.
        container_group = client.container_groups.get(resource_group.name, container_name)
        if str(container_group.provisioning_state).lower() == 'succeeded':
            logging.info("Creation of container group '{}' succeeded.".format(container_name))
        else:
            msg = "Creation of container group '{}' failed. Provisioning state is: {}".format(container_name, container_group.provisioning_state)
            logging.fatal(msg)
            raise RuntimeError(msg)
    logging.info("container create completed")


def get_container_state(client: ContainerInstanceManagementClient, resource_group: ResourceGroup, container_name: str) -> str:
    # Get the provisioning state of the container group.
    container_group = client.container_groups.get(resource_group.name, container_name)
    state = str(container_group.provisioning_state).lower()
    if state == 'succeeded':
        logging.info("Creation of container group '{}' succeeded.".format(container_name))
    else:
        logging.info("Container group '{}' provisioning state is: {}".format(container_name, container_group.provisioning_state))
    return state


def get_container_logs(client: ContainerInstanceManagementClient, resource_group: ResourceGroup, container_name: str) -> str:
    # Get the logs for the container
    logs = client.containers.list_logs(resource_group.name, container_name, container_name)
    logging.info("Logs for container '{0}':".format(container_name))
    with StringIO(logs.content) as f:
        for line in f:
            logging.info(line)
    return logs.content


def delete_container(client: ContainerInstanceManagementClient, resource_group: ResourceGroup, container_name: str) -> None:
    # delete the container
    logging.info(f"deleteing container group: {container_name}")
    result = client.container_groups.begin_delete(resource_group.name, container_name)
    while result.done() is False:
        time.sleep(1)
    logging.info("delete complete")
    return True


def get_credentials(service_account_credentials: dict = None) -> ChainedTokenCredential:
    if service_account_credentials is not None:
        return ChainedTokenCredential(ClientSecretCredential(
            tenant_id=service_account_credentials['azure_tenant_id'],
            client_id=service_account_credentials['azure_client_id'],
            client_secret=service_account_credentials['azure_client_secret']
        ))
    else:
        return ChainedTokenCredential(DefaultAzureCredential(), EnvironmentCredential(), AzureCliCredential())


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('emg clexport aci wrapper')
    try: 
        # print the help
        if req.params.get('print_help'):
            return func.HttpResponse(json.dumps(SAMPLE_REQUEST_BODY), status_code=200, mimetype='application/json')

        r = req.get_json()

        # check required params
        required_params = (
            'subscription_id', 'resource_group', 'image_name', 'container_registry_credentials', 
            'sas_key', 'input_path', 'output_path', 'analysis_package_path', 'rename_file_path',
            )
        for param in required_params:
            if param not in r:
                raise RuntimeError(f"Missing required parameter in your request: '{param}'")

        # get essential params
        subscription_id = r['subscription_id']
        resource_group = r['resource_group']
        image_name = r['image_name']
        sas_key = r['sas_key']
        input_path = r['input_path']
        output_path = r['output_path']
        analysis_package_path = r['analysis_package_path']
        rename_file_path = r['rename_file_path']

        # check container registry credentials
        container_registry_credentials = r['container_registry_credentials']
        required_params = ('server', 'username', 'password')
        if not all([x in container_registry_credentials for x in required_params]):
            raise RuntimeError(f"You must specify all these parameters in 'container_registry_credentials': {str(required_params)}")

        # check for credentials 
        service_account_credentials = None
        if 'service_account_credentials' in r:
            # check that all credentials exit
            required_params = ('azure_client_id', 'azure_tenant_id', 'azure_client_secret')
            service_account_credentials = r['service_account_credentials']
            if not all([x in service_account_credentials for x in required_params]):
                raise RuntimeError(f"You must specify all these parameters in 'service_account_credentials': {str(required_params)}")
        # get optional params
        wait = bool(r['wait']) if 'wait' in r else False
        delete = bool(r['delete']) if 'delete' in r else False
        container_name = str(r['container_name']).lower() if 'container_name' in r else "clexport-{:04d}".format(randint(1, 9999))
        cpu = float(r['cpu']) if 'cpu' in r else 2.0
        mem = float(r['mem']) if 'mem' in r else 4.0

        credential = get_credentials(service_account_credentials)
        client = ContainerInstanceManagementClient(credential, subscription_id)
        rc = ResourceManagementClient(credential, subscription_id)
        rg = rc.resource_groups.get(resource_group)
        command_line = None
        env_vars = {
            'SAS_KEY': sas_key,
            'INPUT_PATH': input_path,
            'OUTPUT_PATH': output_path,
            'ANALYSIS_PACKAGE_PATH': analysis_package_path,
            'RENAME_FILE_PATH': rename_file_path
        }
        # launch the container
        create_container_instance(
            client=client,
            container_name=container_name,
            resource_group=rg,
            image_name=image_name,
            container_registry_credentials=container_registry_credentials,
            command_line=command_line,
            environment_variables=env_vars,
            cpu=cpu,
            mem=mem,
            wait=wait
        )
        # get container logs and delete the container
        state = get_container_state(client, rg, container_name) if wait else None
        logs = get_container_logs(client, rg, container_name) if wait else None
        deleted = delete_container(client, rg, container_name) if (wait and delete) else False

        resp = {
            'status': 'ok',
            'container_name': container_name,
            'resource_group': resource_group,
            'subscription_id': subscription_id,
            'env': env_vars,
            'state': state,
            'logs': logs,
            'wait': wait,
            'deleted': deleted
        }
        return func.HttpResponse(json.dumps(resp), status_code=200, mimetype='application/json')
    except Exception as err:
        traceback.print_exc()
        logging.error(str(err))
        resp = {
            'status': 'error',
            'message': str(err),
            'sample_request': SAMPLE_REQUEST_BODY,
            }
        return func.HttpResponse(json.dumps(resp), status_code=500, mimetype='application/json')

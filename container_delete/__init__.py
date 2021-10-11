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
    'container_name': "unique container instance group name (ie: 'clexport-inst-0001')",

    'service_account_credentials': {
        'tenant_id': "(optional) service account tenant id",
        'client_id': "(optional) service account client id",
        'client_secret': "(optional) service account tenant secret",
    },
}


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
            'subscription_id', 'resource_group', 'container_name',
            )
        for param in required_params:
            if param not in r:
                raise RuntimeError(f"Missing required parameter in your request: '{param}'")

        # get essential params
        subscription_id = r['subscription_id']
        resource_group = r['resource_group']
        container_name = r['container_name']

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
        # delete = bool(r['delete']) if 'delete' in r else False

        credential = get_credentials(service_account_credentials)
        client = ContainerInstanceManagementClient(credential, subscription_id)
        rc = ResourceManagementClient(credential, subscription_id)
        rg = rc.resource_groups.get(resource_group)
        state = get_container_state(client, rg, container_name)
        logs = get_container_logs(client, rg, container_name)
        deleted = delete_container(client, rg, container_name)
        # deleted = delete_container(client, rg, container_name) if (wait and delete) else False

        resp = {
            'status': 'ok',
            'container_name': container_name,
            'resource_group': resource_group,
            'subscription_id': subscription_id,
            'state': state,
            'logs': logs,
            'deleted': deleted,
            'wait': wait,
        }
        return func.HttpResponse(json.dumps(resp), status_code=(200 if deleted else 202), mimetype='application/json')
    except Exception as err:
        traceback.print_exc()
        logging.error(str(err))
        resp = {
            'status': 'error',
            'message': str(err),
            'sample_request': SAMPLE_REQUEST_BODY,
            }
        return func.HttpResponse(json.dumps(resp), status_code=500, mimetype='application/json')

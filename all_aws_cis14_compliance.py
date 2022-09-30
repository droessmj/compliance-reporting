import os
import logging
import argparse
import json

from laceworksdk import LaceworkClient
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger('compliance-results')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))


class NormalizedFinding():
    def __init__(self, account_id, violations, resource_count, severity, title):
        self.title = title
        self.account_id = account_id
        self.violations = violations
        self.resource_count = int(resource_count)
        self.severity = int(severity)

    def __str__(self) -> str:
        return json.dumps(self.__dict__, indent=4, sort_keys=True)

    def __repr__(self) -> str:
        return json.dumps(self.__dict__, indent=4, sort_keys=True)


def get_aws_account_ids(lw_client: LaceworkClient) -> list[str]:
    list_aws_account_ids = list()
    cloud_accounts = lw_client.cloud_accounts.get(type='AwsCfg')

    for account in cloud_accounts['data']:
        roleArn = account['data']['crossAccountCredentials']['roleArn']
        #arn:aws:iam::791529083252:role/lw-md-laceworkcwssarole -> 791529083252 
        account_id  = roleArn.split('::')[1].split(':')[0]
        list_aws_account_ids.append(account_id)

    return list_aws_account_ids


def get_compliance_results(lw_client: LaceworkClient, target_account: str, i: int) -> list[dict]:
    report_results = lw_client.reports.get(
        primaryQueryId=target_account,
        format='json',
        reportType='AWS_CIS_14'
    )
    return (report_results['data'],i) if report_results['data'] else ([{}],i)


def main(args: argparse.Namespace):

    if args.debug:
        logger.setLevel('DEBUG')
        logging.basicConfig(level=logging.DEBUG)

    # Use enviroment variables to instantiate a LaceworkClient instance
    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile
        )
    except Exception:
        raise    

    aws_account_ids = get_aws_account_ids(lw_client)
    logger.debug(f'AWS accounts to retrieve reports for: {aws_account_ids}')
    
    
    total_accounts = len(aws_account_ids)
    normalized_findings = list()
    executor_tasks = list()
    
    # threaded implementation to concurrently assess distinct accounts
    with ThreadPoolExecutor() as executor:

        for i,account_id in enumerate(aws_account_ids):
            executor_tasks.append(executor.submit(get_compliance_results, lw_client, account_id, i))

        for task in as_completed(executor_tasks):

            task_result = task.result()
            account_id = ''
            # don't ask me why this is a list of one...but I'm afraid to hard code it
            for compliance_result in task_result[0]:
                recommendations = compliance_result['recommendations'] if 'recommendations' in compliance_result else []
                for rec in recommendations:
                    account_id = rec['ACCOUNT_ID']
                    normalized_findings.append(
                        NormalizedFinding(
                            rec['ACCOUNT_ID'],
                            rec['VIOLATIONS'],
                            rec['RESOURCE_COUNT'],
                            rec['SEVERITY'],
                            rec['TITLE']
                        )
                )
                logger.debug(f'processed account_id {account_id} - account {task_result[1]} of {total_accounts}')
    
    print(json.dumps(normalized_findings, default = lambda x: x.__dict__, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A script to automatically issue container vulnerability scans to Lacework based on running containers'
    )
    parser.add_argument(
        '--account',
        default=os.environ.get('LW_ACCOUNT', None),
        help='The Lacework account to use'
    )
    parser.add_argument(
        '--subaccount',
        default=os.environ.get('LW_SUBACCOUNT', None),
        help='The Lacework sub-account to use'
    )
    parser.add_argument(
        '--api-key',
        dest='api_key',
        default=os.environ.get('LW_API_KEY', None),
        help='The Lacework API key to use'
    )
    parser.add_argument(
        '--api-secret',
        dest='api_secret',
        default=os.environ.get('LW_API_SECRET', None),
        help='The Lacework API secret to use'
    )
    parser.add_argument(
        '-p', '--profile',
        default='default',
        help='The Lacework CLI profile to use'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging'
    )

    args = parser.parse_args()
    main(args)
"""
This program provides all the search functionality in all data sources.
It is used as command line interface as well from the web interface/APIs.

Execute it as follows to get the possible search options/filter capabilities:

$ search --help

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import re
import json
from typing import List, Iterator
from sqlalchemy import Boolean,  cast, Numeric
from sqlalchemy.sql import text, expression
from sqlalchemy.orm import aliased
from generic import ApplicationContext
from db.tables import Vuln, VulnCpes, Cpe, Cwe, FetchStatus, Capec
from common.models import SearchOptions, SearchInfoType, OutputType, CPE23_REGEX_STR, metrics_mapping

class ValidationError(Exception): ...

# regex used to split the cpe 2.3 into separate pieces
COLUMN_REGEX = re.compile(r'(?<!\\):')
CPE23_REGEX = re.compile(CPE23_REGEX_STR)

# ------------------------------------------------------------------------------
def get_non_empty_opts(opts: SearchOptions) -> dict:
    return {k: v for k, v in vars(opts).items() if v is not None}


# ------------------------------------------------------------------------------
def search_cves(appctx: ApplicationContext, opts: SearchOptions):

    result = {}
    cve_table = aliased(Vuln, name='cve_table')

    with appctx.db as session:

        # prepare the search query
        query = session.query(cve_table)
        # Filter by EPSS score
        if opts.epssScoreGt:
            query = query.filter(cast(cve_table.data['metrics']['epss']['score'].astext, Numeric) > opts.epssScoreGt)
        if opts.epssScoreLt:
            query = query.filter(cast(cve_table.data['metrics']['epss']['score'].astext, Numeric) < opts.epssScoreLt)

        # Filter by EPSS percentile
        if opts.epssPercGt:
            query = query.filter(cast(cve_table.data['metrics']['epss']['percentile'].astext, Numeric) > opts.epssPercGt)
        if opts.epssPercLt:
            query = query.filter(cast(cve_table.data['metrics']['epss']['percentile'].astext, Numeric) < opts.epssPercLt)

        # filter by presense of known_exploited_vulnerabilities
        if opts.exploitable:
            query = query.filter(cve_table.data.has_key('cisaExploitAdd'))

        # filter by the cve IDS, either directly specified in the search options
        if opts.cveId:
            cve_ids = list(map(lambda cve_id: cve_id.upper(), set(opts.cveId)))
            query = query.filter(cve_table.vuln_id.in_(cve_ids))

        # or via the cpe 2.3
        if opts.cpeName:
            cve_ids = search_cves_by_cpes(appctx, opts)
            # if we got CVE IDs from the CPE 2.3 search, we need to filter the results
            if cve_ids:
                query = query.filter(cve_table.vuln_id.in_(cve_ids))
            # otherwise it means that there are no CVE IDs from the CPE 2.3 search
            # thus the query needs to return no records
            else:
                query = query.filter(1 == 0)

        # filter by the keyword search (regex)
        if opts.keywordSearch:
            for idx in range(0, len(opts.keywordSearch)):
                keyword = opts.keywordSearch[idx]
                query = query.filter(text(f'cve_table.description ~* :keyword{idx}').params(**{f'keyword{idx}': keyword}))

        # add filter condition on last modified date
        if opts.lastModStartDate: query = query.filter(cve_table.last_modified_date >= opts.lastModStartDate)
        if opts.lastModEndDate: query = query.filter(cve_table.last_modified_date <= opts.lastModEndDate)

        # add filter condition on published date
        if opts.pubStartDate: query = query.filter(cve_table.published_date >= opts.pubStartDate)
        if opts.pubEndDate: query = query.filter(cve_table.published_date <= opts.pubEndDate)

        # add filter condition on cvss V2 severity
        if opts.cvssV2Severity:
            query = query.filter(cve_table.data['metrics']['cvssMetricV2'].contains([{"baseSeverity": opts.cvssV2Severity.value.upper()}]))

        # add filter condition on cvss V3 severity
        if opts.cvssV3Severity:
            qry_cvss_severity_cond = expression.or_(
                cve_table.data['metrics']['cvssMetricV30'].contains([{"cvssData": {"baseSeverity": opts.cvssV3Severity.value.upper()}}]),
                cve_table.data['metrics']['cvssMetricV31'].contains([{"cvssData": {"baseSeverity": opts.cvssV3Severity.value.upper()}}])
            )
            query = query.filter(qry_cvss_severity_cond)

        # add filter condition on CWE ID
        if opts.cweId:
            cwe_ids = list(map(lambda cwe: re.sub('^\D*','CWE-', cwe), opts.cweId))
            cwe_id_search_arrays_str = ', '.join([f'\'[{{"description":[{{"value": "{cwe_id}"}}]}}]\'::jsonb' for cwe_id in cwe_ids])
            query = query.filter(text(f"cve_table.data->'weaknesses' @> ANY(ARRAY[{cwe_id_search_arrays_str}])"))

        # add the filter for cvss metrics
        if opts.cvssV2Metrics:
            for metric in get_cvss_metric_conditions(opts.cvssV2Metrics, 'V2'):
                query = query.filter(cve_table.data['metrics']['cvssMetricV2'].contains(metric))

        if opts.cvssV3Metrics:
            query = query.filter(
                expression.or_(
                    expression.and_(*[cve_table.data['metrics']['cvssMetricV30'].contains(cond)
                                    for cond in get_cvss_metric_conditions('CVSS:3.0/' + opts.cvssV3Metrics, 'V30')]),
                    expression.and_(*[cve_table.data['metrics']['cvssMetricV31'].contains(cond)
                                    for cond in get_cvss_metric_conditions('CVSS:3.1/' + opts.cvssV3Metrics, 'V31')]),
                )
            )

        # add the pagination
        query = query.offset(opts.pageIdx * opts.pageSize).limit(opts.pageSize)
        result = dict(search=get_non_empty_opts(opts), result=[item.data for item in query.all()])

    return result


# ------------------------------------------------------------------------------
def get_cvss_metric_conditions(cvss_metrics: str, version:str) -> Iterator[dict]:

    metric_mapping = metrics_mapping[version]

    # validate first the input search cvss vector string is a valid one
    if not re.match(metrics_mapping[version]['regex'], cvss_metrics):
        raise ValidationError(f'Invalid CVSS {version} vector: {cvss_metrics}')

    # Brake down into separate vector components
    metrics_dict = dict(metric_str.split(':') for metric_str in cvss_metrics.split('/'))
    for metric, metric_value in metrics_dict.items():

        # if we find a metric in the mapping, then we can return it as a condition
        metric_map_item = metric_mapping.get(metric, {}).get(metric_value, None)
        if metric_map_item:
            yield json.loads(metric_mapping[metric]['json_dict'].replace('{value}', metric_map_item.value))


# ------------------------------------------------------------------------------
def get_vuln_cpes(appctx: ApplicationContext, cpes: List[str], vulnerable: bool = True):

    cpe_items = dict(
        part=None, vendor=None, product=None, version=None, update=None, edition=None,
        language=None, sw_edition=None, target_sw=None, target_hw=None
    )

    cve_cpe_config = aliased(VulnCpes, name='cve_cpe_config')
    cve_cpe_config_cols = [col.name for col in cve_cpe_config.__table__.columns]
    result = {}

    with appctx.db as session:
        for search_cpe in cpes:

            if not CPE23_REGEX.match(search_cpe):
                raise ValidationError(f"Invalid CPE 2.3: {search_cpe}")

            search_cpe_parts = dict(zip(cpe_items.keys(), COLUMN_REGEX.split(search_cpe + ':::::::::::')[2:12]))

            if search_cpe_parts['product'] == '*' and search_cpe_parts['version'] == '*':
                raise ValidationError('Please specify at least product in the CPE')

            query = session.query(cve_cpe_config)
            for cpe_item in cpe_items.keys():

                # if we need to search by the particular item
                if search_cpe_parts[cpe_item] and search_cpe_parts[cpe_item] != '*':

                    # here a special treatment on the version
                    if cpe_item == 'version':
                        qry_ver_cond = expression.or_(
                            cve_cpe_config.version == search_cpe_parts[cpe_item],
                            # cve_cpe_config.version == '-',
                            expression.and_(
                                cve_cpe_config.version == '*',
                                text("ver_pad(coalesce(cve_cpe_config.version_gt, '0'), 7) < ver_pad(:ver, 7)"),
                                text("ver_pad(coalesce(cve_cpe_config.version_ge, '0'), 7) <= ver_pad(:ver, 7)"),
                                text("ver_pad(coalesce(cve_cpe_config.version_lt, 'zzzzzzz'), 7) > ver_pad(:ver, 7)"),
                                text("ver_pad(coalesce(cve_cpe_config.version_le, 'zzzzzzz'), 7) >= ver_pad(:ver, 7)")
                            )
                        )
                        query = query.filter(qry_ver_cond).params(ver=search_cpe_parts[cpe_item])

                    # and for the rest parts we search the same way
                    # AND (column = input OR column = '*')
                    else:
                        # in case vendor was specified as '*' we make a stricted search on product
                        # as there are configurations where only vendor is specified in the CPE while the product is '*'
                        if cpe_item == 'product' and search_cpe_parts['vendor'] == '*':
                            query = query.filter(expression.or_(getattr(cve_cpe_config, cpe_item) == search_cpe_parts[cpe_item]))
                        else:
                            query = query.filter(expression.or_(getattr(cve_cpe_config, cpe_item) == search_cpe_parts[cpe_item],
                                                                getattr(cve_cpe_config, cpe_item) == '*'))

            if vulnerable:
                query = query.filter(cve_cpe_config.vulnerable == True)

            result[search_cpe] = [{key: getattr(row, key) for key in cve_cpe_config_cols} for row in query.all()]

    return result


# ------------------------------------------------------------------------------
def search_cves_by_cpes(appctx: ApplicationContext, opts: SearchOptions):

    # first get the cve configurations that are vulnerable for the provided list of cpes
    vuln_config_cpes = get_vuln_cpes(appctx, [opts.cpeName], vulnerable=opts.vulnerable)

    # TODO: In case we would implement the feature of checking/making sure also the
    # vulnerable CPEs is in relation with the other CPEs
    # (i.e. a CVE for Adobe Reader needs to run on specific OS or hardware)
    # then here is the place to do it.

    # return a list of cve IDs that are vulnerable for the provided list of cpes
    return list(set([item['vuln_id'] for item in vuln_config_cpes[opts.cpeName]]))


# ------------------------------------------------------------------------------
def search_cpes(appctx: ApplicationContext, opts: SearchOptions):

    cpe_items = dict(
        part=None, vendor=None, product=None, version=None, update=None, edition=None,
        language=None, sw_edition=None, target_sw=None, target_hw=None
    )

    result = {}
    cpe_table = aliased(Cpe, name='cpe_table')

    with appctx.db as session:

        query = session.query(cpe_table)

        # add filter condition on the keywords search
        if opts.keywordSearch:

            for idx, keyword in enumerate(opts.keywordSearch):
                query = query.filter(text(f'cpe_table.title_en ~* :keyword{idx}').params(**{f'keyword{idx}':keyword}))

        # add filter condition on last modified date
        if opts.lastModStartDate:
            query = query.filter(cpe_table.last_modified_date >= opts.lastModStartDate)

        if opts.lastModEndDate:
            query = query.filter(cpe_table.last_modified_date <= opts.lastModEndDate)

        # add filter condition for the deprecated part
        if opts.deprecated:
            query = query.filter(cpe_table.data['deprecated'].astext.cast(Boolean) == True)
        else:
            query = query.filter(cpe_table.data['deprecated'].astext.cast(Boolean) == False)

        # add filter condition for the cpe 23 part
        if opts.cpeName:

            search_cpe = opts.cpeName

            if not CPE23_REGEX.match(search_cpe):
                raise ValidationError(f"Invalid CPE 2.3 specification: {search_cpe}")

            search_cpe_parts = dict(zip(cpe_items.keys(), COLUMN_REGEX.split(search_cpe + ':::::::::::')[2:12]))

            if search_cpe_parts['vendor'] == '*' and search_cpe_parts['product'] == '*':
                raise ValidationError('Please specify at least vendor or product in the CPE')

            for cpe_item in cpe_items.keys():
                # if we need to search by the particular item
                if search_cpe_parts[cpe_item] and search_cpe_parts[cpe_item] != '*':
                    if cpe_item == 'product' and search_cpe_parts['vendor'] == '*':
                        query = query.filter(getattr(cpe_table, cpe_item).like(search_cpe_parts[cpe_item].replace('*', '%')))
                    else:
                        query = query.filter(expression.or_(getattr(cpe_table, cpe_item).like(search_cpe_parts[cpe_item].replace('*', '%')),
                                                            getattr(cpe_table, cpe_item) == '*'))

        query = query.offset(opts.pageIdx * opts.pageSize).limit(opts.pageSize)
        result = dict(search=get_non_empty_opts(opts), result=[row.data for row in query.all()])

    return result


# ------------------------------------------------------------------------------
def search_cwes(appctx: ApplicationContext, opts: SearchOptions):

    result = {}

    cwe_table = aliased(Cwe, name='cwe_table')

    with appctx.db as session:

        # prepare the search query
        query = session.query(cwe_table)

        # add the filters
        if opts.keywordSearch:
            for idx, keyword in enumerate(opts.keywordSearch):
                query = query.filter(text(f"cwe_table.description ~* :keyword{idx}")).params(**{f'keyword{idx}':keyword})

        if opts.cweId:
            # remove any letters and '-' from the IDs in case those were specified
            cwe_id_fix = re.compile(r'[A-Za-z\-]*')
            cwe_ids = list(map(lambda cwe: cwe_id_fix.sub('', cwe), opts.cweId))

            query = query.filter(cwe_table.cwe_id.in_(cwe_ids))

        query = query.offset(opts.pageIdx * opts.pageSize).limit(opts.pageSize)
        result = dict(search=get_non_empty_opts(opts), result=[row.data for row in query.all()])

    return result


# ------------------------------------------------------------------------------
def search_capec(appctx: ApplicationContext, opts: SearchOptions):

    result = {}

    capec_table = aliased(Capec, name='capec_table')

    with appctx.db as session:

        # prepare the search query
        query = session.query(capec_table)

        # search by the keywords
        if opts.keywordSearch:
            for idx, keyword in enumerate(opts.keywordSearch):
                query = query.filter(text(f"capec_table.description ~* :keyword{idx}")).params(**{f'keyword{idx}':keyword})

        # search by the CAPEC IDs
        if opts.capecId:
            # remove any letters and '-' from the IDs in case those were specified
            capec_id_fix = re.compile(r'[A-Za-z\-]*')
            capec_ids = list(map(lambda capec: capec_id_fix.sub('', capec), opts.capecId))

            query = query.filter(capec_table.capec_id.in_(capec_ids))

        query = query.offset(opts.pageIdx * opts.pageSize).limit(opts.pageSize)
        result = dict(search=get_non_empty_opts(opts), result=[row.data for row in query.all()])
    return result


# ------------------------------------------------------------------------------
def search_data(appctx, opts: SearchOptions):

    search_results = {}

    # search the data based on the input criterias
    if   opts.searchInfo == SearchInfoType.status:  search_results = get_fetch_status(appctx)
    elif opts.searchInfo == SearchInfoType.cve:     search_results = search_cves(appctx, opts)
    elif opts.searchInfo == SearchInfoType.cpe:     search_results = search_cpes(appctx, opts)
    elif opts.searchInfo == SearchInfoType.cwe:     search_results = search_cwes(appctx, opts)
    elif opts.searchInfo == SearchInfoType.capec:   search_results = search_capec(appctx, opts)

    return search_results


# ------------------------------------------------------------------------------
def results_output(opts: SearchOptions, search_results):

    if opts.searchInfo == SearchInfoType.status:  results_output_status(opts, search_results)
    elif opts.output == OutputType.id:            results_output_id(opts, search_results)
    elif opts.output == OutputType.json:          results_output_json(search_results)


# ------------------------------------------------------------------------------
def results_output_id(opts: SearchOptions, search_results):

    key_names_map = {
        SearchInfoType.cve:     'id',
        SearchInfoType.cpe:     'cpeName',
        SearchInfoType.cwe:     'ID',
        SearchInfoType.capec:   'ID',
    }

    key = key_names_map[opts.searchInfo]
    ids = [item[key] for item in search_results['result']]

    print(*list(set(ids)), sep='\n')


# ------------------------------------------------------------------------------
def results_output_json(search_results):
    print(json.dumps(search_results, default=str))


# ------------------------------------------------------------------------------
def get_fetch_status(appctx):

    with appctx.db as session:
        data = session.query(FetchStatus).all()

        return {
            row.name: dict(update_date=str(row.last_modified_date), count=row.stats.get('total_records', 'N/A'))
            for row in data
        }


# ------------------------------------------------------------------------------
def results_output_status(opts: SearchOptions, search_results):

    if opts.output == OutputType.id:
        for item_key, item_value in search_results.items():
            print(f"data:{item_key} count records:{item_value['count']} update_date: {item_value['update_date']}")
    elif opts.output == OutputType.json:
        print(json.dumps(search_results))

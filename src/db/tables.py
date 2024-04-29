"""
DB Schema (Tables and Indexes) definitions

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

# coding: utf-8
from sqlalchemy import (Column, DateTime, Integer, String, Boolean, Float, text,
                        UniqueConstraint, Index, Text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql.json import JSONB

Base = declarative_base()
metadata = Base.metadata


# ------------------------------------------------------------------------------
#  Definition of application tables
# ------------------------------------------------------------------------------
class FetchStatus(Base):
    __tablename__ = 'fetch_status'
    __table_args__ = (
        UniqueConstraint('name', name='fetch_status_uix_1'),
        {u'comment': u'Table that contains the fetch status for different keys'}
    )
    id = Column(Integer, primary_key=True)
    name = Column(String(40), nullable=False, comment=u"the name of the status")
    sys_creation_date = Column(DateTime, nullable=False, server_default=text('current_timestamp'))
    last_modified_date = Column(DateTime, nullable=False, comment=u'Date when record was modified.')
    stats = Column(JSONB, comment=u'JSON column for additional details')


# ------------------------------------------------------------------------------
class Vuln(Base):
    __tablename__ = 'vuln'
    __table_args__ = (
        UniqueConstraint('vuln_id', name='vuln_uix_1'),
        Index('vuln_idx1', 'description', postgresql_using='gist'),
        {u'comment': u'Table that contains the list of Vulnerabilities'}
    )

    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(20), index=True)
    sys_creation_date = Column(DateTime, nullable=False, server_default=text('current_timestamp'))
    published_date = Column(DateTime, index=True, nullable=False, comment=u'Date when record published.')
    last_modified_date = Column(DateTime, index=True, nullable=False, comment=u'Date when record was modified.')
    source = Column(String(100), comment=u"the source of the vulnerability")
    description = Column(Text, comment=u"the description of the CVE")
    data = Column(JSONB, comment=u'Vuln JSON representation')


# ------------------------------------------------------------------------------
class VulnCpes(Base):
    __tablename__ = 'vuln_cpes'
    __table_args__ = (
        Index('vuln_cpe_idx1', 'product', 'version', 'vendor', ),
        {u'comment': u'Table that contains the list of Vulnerabilities'}
    )

    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(20), index=True)
    cpe = Column(String(256), nullable=True)
    sys_creation_date = Column(DateTime, nullable=False, server_default=text('current_timestamp'))
    cond = Column(String(10), nullable=False, comment=u"The condition between the records of the same group AND/OR")
    negate = Column(Boolean, default=False, comment=u'Indicate if the condition result is to be negated')
    vulnerable = Column(Boolean, comment=u'Indicate if the specified CPE is vulnerable')
    group_id = Column(Integer)
    parent_group_id = Column(Integer, nullable=False)
    part = Column(String(1), comment=u"the part of CPE")
    vendor = Column(String(128), comment=u"the vendor of CPE")
    product = Column(String(128), comment=u"the product of CPE")
    version = Column(String(128), comment=u"the version of CPE")
    version_lt = Column(String(128), comment=u"the little version of CPE")
    version_le = Column(String(128), comment=u"the little or equal version of CPE")
    version_gt = Column(String(128), comment=u"the greater version of CPE")
    version_ge = Column(String(128), comment=u"the greater or equal version of CPE")
    update = Column(String(128), comment=u"the update of CPE")
    edition = Column(String(128), comment=u"the edition of CPE")
    language = Column(String(128), comment=u"the language of CPE")
    sw_edition = Column(String(128), comment=u"the sw_edition of CPE")
    target_sw = Column(String(128), comment=u"the target_sw of CPE")
    target_hw = Column(String(128), comment=u"the target_hw of CPE")


# ------------------------------------------------------------------------------
class Cpe(Base):
    __tablename__ = 'cpe'
    __table_args__ = (
        UniqueConstraint('name', name='cpe_uix_1'),
        Index('cpe_idx1', 'product', 'version', 'vendor'),
        Index('cpe_idx2', 'title_en'),
        {u'comment': u'Table that contains the list of CPEs'}
    )

    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False, comment=u"the name of the CPE")
    name_id = Column(String(256), nullable=False, comment=u"the name ID of the CPE")
    title_en = Column(String(512), index=True, comment=u"the English title of the CPE")
    sys_creation_date = Column(DateTime, nullable=False, server_default=text('current_timestamp'))
    created = Column(DateTime, index=True, nullable=False, comment=u'Date when the CPE record was created.')
    last_modified_date = Column(DateTime, index=True, nullable=False, comment=u'Date when the CPE record was modified.')
    part = Column(String(1), nullable=False, comment=u"the part of CPE")
    vendor = Column(String(128), nullable=False, comment=u"the vendor of CPE")
    product = Column(String(128), nullable=False, comment=u"the product of CPE")
    version = Column(String(128), nullable=False, comment=u"the version of CPE")
    update = Column(String(128), comment=u"the update of CPE")
    edition = Column(String(128), comment=u"the edition of CPE")
    language = Column(String(128), comment=u"the language of CPE")
    sw_edition = Column(String(128), comment=u"the sw_edition of CPE")
    target_sw = Column(String(128), comment=u"the target_sw of CPE")
    target_hw = Column(String(128), comment=u"the target_hw of CPE")
    data = Column(JSONB, comment=u'CPE JSON representation')


# ------------------------------------------------------------------------------
class Cwe(Base):
    __tablename__ = 'cwe'
    __table_args__ = (
        Index('cwe_idx1', 'name'),
        Index('cwe_idx2', 'description'),
        {u'comment': u'Table that contains the list of CWEs'}
    )

    id = Column(Integer, primary_key=True)
    cwe_id = Column(Integer, nullable=False, index=True, comment=u'The ID of the CWE')
    name = Column(String(256), nullable=False, comment=u"the name of the CWE")
    status = Column(String(128), comment=u"the status of the CWE")
    description = Column(Text, comment=u"the description of the CWE")
    data = Column(JSONB, comment=u'CWE JSON representation')


# ------------------------------------------------------------------------------
class Capec(Base):
    __tablename__ = 'capec'
    __table_args__ = (
        Index('capec_idx1', 'name'),
        Index('capec_idx2', 'description'),
        {u'comment': u'Table that contains the list of CWEs'}
    )

    id = Column(Integer, primary_key=True)
    capec_id = Column(Integer, nullable=False, index=True, comment=u'The ID of the CAPEC')
    name = Column(String(256), nullable=False, comment=u"the name of the CAPEC")
    status = Column(String(128), comment=u"the status of the CAPEC")
    description = Column(Text, comment=u"the description of the CAPEC")
    data = Column(JSONB, comment=u'CAPEC JSON representation')

# ------------------------------------------------------------------------------
class Epss(Base):
    __tablename__ = 'epss'
    __table_args__ = (
        Index('epss_idx1', 'cve_id'),
        {u'comment': u'Table that contains the list of EPSS'}
    )

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), index=True, comment=u'The ID of the CVE')
    epss_score = Column(Float, nullable=False, comment=u"the score of the epss")
    percentile = Column(Float, nullable=False, comment=u"the percentile of the epss")
    date = Column(DateTime, nullable=False, comment=u"Date when the EPSS record has been downloaed")
    changed = Column(Boolean, comment=u'indicate if epss_score has been changed')

#!/usr/bin/env python
#
# sudo yum-builddep  MySQL-python / sudo apt-get build-dep python-mysqldb
# Prereq:
#  pip install begins saratoga twisted.enterprise.adbapi MySQL-python
#
# usage ./repute.py --help
#
# URLs are versioned:
#
# wget -S --header 'Accept: application/reputon+json' http://localhost:8000/v1/reporter/dan -O -


import begin

from saratoga.api import SaratogaAPI
from saratoga.outputFormats import OutputRegistry
from twisted.enterprise import adbapi
from twisted.internet import defer
import itertools
import json

class DKIM(object):
    class v1(object):

        @defer.inlineCallbacks
        def report_GET(self, request, params, reporter, subject):
            # hint to aid overabuse of service
            request.setHeader('Cache-control', 'max-age=1')

            query1 = '''SELECT ratio_high, UNIX_TIMESTAMP(updated), rate_samples
                        FROM   predictions
                        WHERE  name = %(subject)s
                        AND    reporter = 0'''
            
            query2 = '''SELECT daily_limit_low
                        FROM   predictions JOIN reporters ON reporters.id=predictions.reporter
                        WHERE  predictions.name = %(subject)s
                        AND    reporters.name   = %(reporter)s '''
            
            res1, res2 = yield defer.DeferredList([ self.cp.runQuery(query1, {'subject': subject }),
                                          self.cp.runQuery(query2, {'subject': subject, 'reporter': reporter }) ])

            reputons = {
                "assertion": "spam",
                "rated": subject,
                "identity": "dkim",
            }

            if res1[0] and res1[1]:
                res1 = res1[1][0]
                reputons["rating"] = res1[0]
                reputons["sample-size"] = res1[2]
                reputons["generated"] = res1[1]

            if res2[0] and res2[1]:
                res2 = res2[1][0]
                reputons['rate'] = res2[0]

            defer.returnValue(
                {
                    "application": "email-id",
                    "reputons": [ reputons ]
                })


        @defer.inlineCallbacks
        def domain_reporter_GET(self, request, params, domain, reporter):

            request.setHeader('Cache-control', 'max-age=1')

            fields = [ 'name', 'updated', 'rate_samples', 'rate_max', 'rate_avg', 'rate_stddev', 'rate_high', 'ratio_max', 'ratio_avg', 'ratio_stddev', 'ratio_high', 'daily_limit_high', 'daily_limit_low', 'today_mail', 'today_spam' ]

            query = 'SELECT ' + ','.join('predictions.' + f for f in fields)  + '''
                       FROM  domains JOIN predictions ON domains.id=predictions.domain
                                     JOIN reporters   ON reporters.id=predictions.reporter 
                       WHERE domains.name = %(domain)s
                       AND   reporters.name = %(reporter)s '''
            
            rows = yield self.cp.runQuery(query, {'domain': domain, 'reporter': reporter})

            if rows:
                ret = dict(itertools.izip(fields, rows[0]))
            else:
                ret = 0
            defer.returnValue(ret)

        @defer.inlineCallbacks
        def reporter_GET(self, request, params, reporter):

            request.setHeader('Cache-control', 'max-age=1')

            fields = [ 'reporter', 'name', 'updated', 'rate_samples', 'rate_max',
                       'rate_avg', 'rate_stddev', 'rate_high', 'ratio_max',
                       'ratio_avg', 'ratio_stddev', 'ratio_high', 'daily_limit_high',
                       'daily_limit_low', 'today_mail', 'today_spam' ]

            query = 'SELECT domains.name,' + ','.join('predictions.' + f for f in fields)  + '''
                     FROM   predictions JOIN reporters ON reporters.id=predictions.reporter
                            LEFT JOIN domains ON predictions.domain = domains.id
                     WHERE  reporters.name = %(reporter)s '''

            fields = ['domain'] +  fields

            rows = yield self.cp.runQuery(query, { 'reporter' : reporter } )
            if rows:
                ret = dict(itertools.izip(fields, rows[0]))
                request.setHeader('Last-modified', rows[0][3].strftime("%A, %d, %B %Y %H:%M GMT"))
            else:
                ret = False
            defer.returnValue(ret)

DKIM_APIDef = {
    "metadata": {"versions": [1]},
    "endpoints": [
        {
            "endpoint": 'report/([^/]*)/(.*)',
            "func": 'report',
            "getProcessors": [{"versions": [1]}]
        },
        {
            "endpoint": 'domain/([^/]*)/([^/]*)',
            "func": 'domain_reporter',
            "getProcessors": [{"versions": [1]}]
        },
        {
            "endpoint": 'reporter/([^/]*)',
            "func": 'reporter',
            "getProcessors": [{"versions": [1]}]
        },
    ]
}


class Database:
    def __init__(self,user,password,host,database):
        self.cp = adbapi.ConnectionPool('MySQLdb',user=user, passwd=password,
                                      host=host,
                                      db=database)
    
def jsonDateFormatter(status, data):

    def _todate(obj):
        return obj.strftime('%Y%m%d %H%M%S')

    resp = {
        "status": status,
        "data": data
    }

    return json.dumps(resp, default=_todate)

@begin.start
def run(host="localhost", user="opendkim", password="opendkim", database="opendkim", bindAddress='', bindPort=8000):
    "This program runs a web server to retrieve reputation data from the opendkim database"

    outputRegistry = OutputRegistry('application/reputon+json')
    outputRegistry.register('application/reputon+json', jsonDateFormatter)
    outputRegistry.register('text/html', jsonDateFormatter)
    api = SaratogaAPI(DKIM, DKIM_APIDef, serviceClass=Database(user=user, password=password, host=host, database=database),
                      outputRegistry=outputRegistry)
    api.run(port=bindPort)


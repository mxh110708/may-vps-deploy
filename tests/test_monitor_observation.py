"""Snapshot classification uses synthetic data only; no server or host commands."""
import copy
import datetime
import json
import unittest

from observe_may_monitor import snapshot_evidence


class SnapshotEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.capture=datetime.datetime.now(datetime.timezone.utc)
        self.ids=['fixture-'+str(i) for i in range(5)]
        self.snapshot={'captured_at':self.capture.isoformat(),'nodes':[
            {'uuid':node,'online':True,'report_at':(self.capture-datetime.timedelta(seconds=2)).isoformat(),'metrics':{
                'cpu_percent':0,'memory_used':0,'memory_total':1024,'upload_per_sec':0,'download_per_sec':0,'upload_total':0,'download_total':0},
             'token':'must-not-be-retained','address':'must-not-be-retained'} for node in self.ids]}

    def test_healthy_zero_metrics_and_no_per_node_log(self):
        evidence=snapshot_evidence(self.snapshot,self.ids)
        self.assertEqual((evidence['online'],evidence['fresh']),(5,5))
        self.assertEqual(evidence['snapshot_issue_counts'],{})
        self.assertNotIn('node_evidence',evidence)

    def test_future_report_reproduces_five_online_four_fresh(self):
        self.snapshot['nodes'][-1]['report_at']=(self.capture+datetime.timedelta(microseconds=1)).isoformat()
        evidence=snapshot_evidence(self.snapshot,self.ids)
        self.assertEqual((evidence['online'],evidence['fresh']),(5,4))
        self.assertEqual(evidence['min_report_age_seconds'],-.000001)
        self.assertEqual(evidence['snapshot_issue_counts'],{'report_from_future':1})
        self.assertEqual(evidence['node_evidence'][-1]['reasons'],['report_from_future'])
        self.assertNotIn('must-not-be-retained',str(evidence))
        for node in evidence['node_evidence']:
            self.assertNotIn('uuid',node)
            self.assertNotIn('token',node)
            self.assertNotIn('address',node)

    def test_stamping_after_the_same_arrival_makes_all_reports_fresh(self):
        self.snapshot['nodes'][-1]['report_at']=(self.capture+datetime.timedelta(microseconds=1)).isoformat()
        self.snapshot['captured_at']=(self.capture+datetime.timedelta(microseconds=2)).isoformat()
        self.assertEqual(snapshot_evidence(self.snapshot,self.ids)['fresh'],5)

    def test_failure_reasons_remain_distinct(self):
        scenarios=[('report_at',None,'missing_report'),('report_at','bad-time','invalid_report_time'),
                   ('report_at',(self.capture-datetime.timedelta(seconds=16)).isoformat(),'stale_report'),
                   ('metrics',None,'missing_metrics'),('metrics',{},'invalid_metrics'),('online',False,'offline')]
        for key,value,reason in scenarios:
            with self.subTest(reason=reason):
                snapshot=copy.deepcopy(self.snapshot);snapshot['nodes'][-1][key]=value
                evidence=snapshot_evidence(snapshot,self.ids)
                self.assertEqual(evidence['fresh'],4)
                self.assertEqual(evidence['snapshot_issue_counts'],{reason:1})

    def test_invalid_metrics_never_become_healthy(self):
        for key,value in [('cpu_percent',101),('cpu_percent',float('nan')),('cpu_percent',float('inf')),('memory_used',1025),('memory_total',0),('upload_per_sec',-1),('upload_total',10**1000)]:
            with self.subTest(key=key,value=value):
                snapshot=copy.deepcopy(self.snapshot);snapshot['nodes'][-1]['metrics'][key]=value
                evidence=snapshot_evidence(snapshot,self.ids)
                self.assertEqual(evidence['snapshot_issue_counts'],{'invalid_metrics':1})
                json.dumps(evidence,allow_nan=False)

    def test_bad_snapshot_shape_is_a_read_error_and_untrusted_fields_are_not_logged(self):
        for snapshot in ({},None,{'captured_at':None,'nodes':[]},{'captured_at':self.capture.isoformat(),'nodes':[None]}):
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(ValueError):snapshot_evidence(snapshot,self.ids)
        self.snapshot['nodes'][-1]['report_at']='must-not-be-retained'
        self.assertNotIn('must-not-be-retained',str(snapshot_evidence(self.snapshot,self.ids)))

    def test_expected_scope_and_duplicate_or_missing_nodes(self):
        snapshot=copy.deepcopy(self.snapshot);snapshot['nodes'].pop()
        evidence=snapshot_evidence(snapshot,self.ids)
        self.assertEqual(evidence['fresh'],4)
        self.assertEqual(evidence['node_evidence'][-1]['reasons'],['missing_node','offline','missing_report','missing_metrics'])
        snapshot=copy.deepcopy(self.snapshot);snapshot['nodes'].append(copy.deepcopy(snapshot['nodes'][-1]))
        self.assertEqual(snapshot_evidence(snapshot,self.ids)['snapshot_issue_counts'],{'duplicate_node':1})
        self.assertEqual(snapshot_evidence(self.snapshot,self.ids[:1])['fresh'],1)

    def test_age_limit_is_inclusive_and_timezones_required(self):
        self.snapshot['nodes'][-1]['report_at']=(self.capture-datetime.timedelta(seconds=15)).isoformat()
        self.assertEqual(snapshot_evidence(self.snapshot,self.ids)['fresh'],5)
        self.snapshot['nodes'][-1]['report_at']=self.capture.replace(tzinfo=None).isoformat()
        self.assertEqual(snapshot_evidence(self.snapshot,self.ids)['snapshot_issue_counts'],{'invalid_report_time':1})


if __name__=='__main__':unittest.main()

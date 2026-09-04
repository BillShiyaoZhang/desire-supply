"""Regression checks for administrator history, attribution and read boundaries."""
from copy import deepcopy
from uuid import UUID
import pytest
from desire_platform.internal_pilot.admin_demand_timeline import AdminDemandCursorCodec, PsycopgAdminDemandTimelineService, project_timeline, _utc
from desire_platform.internal_pilot.editor.contracts import EditorPrincipal, EditorServiceError
from desire_platform.internal_pilot.editor.http import EditorHttpApi, HttpRequest
from desire_platform.internal_pilot.editor.asgi import _query_values

U='00000000-0000-4000-8000-000000000001'
S='00000000-0000-4000-8000-000000000002'
D='00000000-0000-4000-8000-000000000003'
O='00000000-0000-4000-8000-000000000004'
R='00000000-0000-4000-8000-000000000005'
T='2026-09-04T00:00:00.000000Z'

@pytest.fixture
def principal():
    return EditorPrincipal(user_id=U,session_id=S,organization_id=None,role_codes=('ACCESS_ADMIN',),workspace_id='platform:'+U,workspace_kind='PLATFORM',platform_duty_codes=('ACCESS_ADMIN',),principal_marker_sha256=b'm'*32)

@pytest.fixture
def demand():
    return dict(demand_id=D,organization_id=O,creator_user_id=U,title='宠物喂食需求',status='DRAFT',aggregate_version=1,created_at=T,updated_at=T,expires_at='2026-12-04T00:00:00Z')

@pytest.fixture
def facts():
    return {'DEMAND':{'names':{U:'owner'}},'MATCHING':{'names':{}},'TRUST':{'names':{}}}

def event(**overrides):
    return dict(dict(event_id=R,action='CreateDemand',actor_kind='USER',actor_user_id=U,role_code='DEMAND_OWNER',target_kind='Demand',target_id=D,occurred_at=T,after_status='DRAFT',original_actor_user_id=None),**overrides)

def test_draft_has_no_fabricated_progress(demand,facts):
    result=project_timeline(demand,facts,{'events':[event()]},T)
    assert result['stages'][0]['status']=='IN_PROGRESS'
    assert all(s['status']=='PENDING' for s in result['stages'][1:5])
    assert all(s['status']=='NOT_IMPLEMENTED' and s['event_count']==0 for s in result['stages'][5:])
    assert result['demand']['blocker_codes']==['WAITING_FOR_SUBMISSION']

def test_matching_is_not_agreement_delivery_or_payment(demand,facts):
    demand['status']='MATCHED'
    result=project_timeline(demand,facts,{'events':[]},T)
    assert result['demand']['current_stage']=='AGREEMENT'
    assert result['demand']['blocker_codes']==['AGREEMENT_NOT_IMPLEMENTED']
    assert next(c for c in result['coverage'] if c['source']=='FINANCE')['status']=='PARTIAL'

def test_system_lineage_and_safe_audit_whitelist(demand,facts):
    row=event(action='RequestMatchingSystem',actor_kind='SYSTEM',actor_user_id=None,original_actor_user_id=U,safe_attributes={'token':'SECRET'},trace_id='SECRET')
    result=project_timeline(demand,facts,{'events':[row]},T)
    actual=result['events'][0]
    assert actual['actor_user_id'] is None and actual['actor_role']=='SYSTEM'
    assert actual['details']['original_actor_user_id']==U
    assert 'SECRET' not in str(result)

def test_invitation_role_uses_exact_durable_creator(demand,facts):
    facts['MATCHING']['invitations']=[dict(id=R,creator_user_id=R,created_by_user_id=U)]
    row=event(action='ACCEPT_INVITATION',actor_user_id=R,role_code=None,target_kind='Invitation',target_id=R,original_actor_user_id=R)
    result=project_timeline(demand,facts,{'events':[row]},T)
    assert result['events'][0]['actor_role']=='CREATOR'
    assert next(p for p in result['participants'] if p['user_id']==R)['roles']==['CREATOR']

def test_historical_failed_attempt_does_not_block_current_attempt(demand,facts):
    demand['status']='MATCHING'
    facts['MATCHING'].update(matching_attempts=[dict(id=D,status='OPEN',created_at=T,current_match_run_id=R)],match_runs=[dict(id=O,status='FAILED',eligible_count=None),dict(id=R,status='COMPLETED',eligible_count=1)],match_jobs=[dict(id=O,match_run_id=O,status='FAILED')],invitations=[dict(id=S,attempt_id=D,status='ACCEPTED',creator_user_id=R,created_by_user_id=U)])
    result=project_timeline(demand,facts,{'events':[]},T)
    assert result['demand']['blocker_codes']==['WAITING_FOR_SELECTOR']
    assert result['demand']['current_stage']=='SELECTION'

def test_failed_handoff_is_visible_before_matching_attempt_exists(demand,facts):
    demand['status']='MATCHING'
    facts['DEMAND'].update(matching_requests=[dict(id=R,requested_at=T)],matching_requested_deliveries=[dict(id=S,matching_request_id=R,status='FAILED',last_failure_code='LEASE_EXPIRED',terminal_at=T,updated_at=T)])
    result=project_timeline(demand,facts,{'events':[]},T)
    assert result['demand']['blocker_codes']==['MATCHING_JOB_FAILED']
    assert result['events'][0]['action']=='MatchingDeliveryFailed'

def test_finance_confirmation_counts_only_current_cycle(demand,facts):
    demand['status']='FUNDING_PENDING'
    facts['DEMAND'].update(manual_funding_review_cases=[dict(id=D,status='DISCREPANCY',created_at='2026-09-03T00:00:00Z'),dict(id=S,status='PENDING',created_at=T)],manual_funding_confirmations=[dict(id=O,funding_review_id=D,actor_user_id=R,confirmed_at=T)])
    assert project_timeline(demand,facts,{'events':[]},T)['demand']['blocker_codes']==['WAITING_FOR_FINANCE_REVIEW']

def test_review_reason_survives_audit_fact_deduplication(demand,facts):
    facts['DEMAND']['demand_reviews']=[dict(id=S,reviewer_user_id=U,reviewed_at=T,decision='NEEDS_CHANGES',reason_codes=['SCOPE_UNCLEAR'],required_field_codes=['scope'])]
    row=event(action='RequestDemandChanges',role_code='OPERATIONS_REVIEWER')
    result=project_timeline(demand,facts,{'events':[row]},T)
    assert len(result['events'])==1
    assert result['events'][0]['details']['reason_code']=='SCOPE_UNCLEAR'
    assert 'scope' in result['events'][0]['summary']

def test_missing_audit_uses_stable_identifiable_fact(demand,facts):
    facts['DEMAND']['demand_review_assignments']=[dict(id=R,reviewer_user_id=U,created_at=T)]
    first=project_timeline(demand,facts,{'events':[]},T)
    assert first==project_timeline(demand,facts,{'events':[]},T)
    assert UUID(first['events'][0]['event_id']).version==5
    assert first['events'][0]['details']['result_code']=='RECORDED'

def test_timestamp_normalization_preserves_microsecond_order():
    assert _utc('2026-09-04T00:00:00Z')<_utc('2026-09-04T00:00:00.1Z')
    assert _utc('2026-09-04T01:00:00+01:00')==T

def test_cursor_binds_signature_route_session_and_workspace(principal):
    codec=AdminDemandCursorCodec(b'k'*32)
    token=codec.encode(principal,D,3,'snapshot')
    assert codec.decode(token,principal,D)['p']==3
    bad=token[:-2]+('AA' if token[-2:]!='AA' else 'BB')
    for value,route in ((bad,D),(token,'list')):
        with pytest.raises(EditorServiceError) as caught: codec.decode(value,principal,route)
        assert caught.value.code=='INVALID_CURSOR'
    other=deepcopy(principal)
    object.__setattr__(other,'session_id',R)
    with pytest.raises(EditorServiceError): codec.decode(token,other,D)

def test_non_admin_never_checks_out_db():
    class NoConnections:
        def checkout(self): raise AssertionError('unauthorized checkout')
    service=PsycopgAdminDemandTimelineService(connections=NoConnections(),cursor_codec=AdminDemandCursorCodec(b'k'*32))
    owner=EditorPrincipal(user_id=U,session_id=S,organization_id=O,role_codes=('DEMAND_OWNER',))
    with pytest.raises(EditorServiceError) as caught: service.list_demands(principal=owner)
    assert caught.value.status==404

def test_http_uses_server_principal_and_rejects_role_in_body(principal):
    class Service:
        def list_demands(self,**kwargs):
            assert kwargs['principal'] is principal
            return dict(items=[],has_more=False,next_cursor=None)
    api=EditorHttpApi(service=None,admin_demand_service=Service())
    path='/v1/app/admin/demands'
    response=api.handle(request=HttpRequest('GET',path,{}, {},{'limit':'3'}),principal=principal)
    assert response.status==200 and response.headers['Cache-Control']=='no-store'
    denied=api.handle(request=HttpRequest('GET',path,{}, {'role_codes':['ACCESS_ADMIN']}),principal=principal)
    assert denied.status==422

def test_asgi_query_keys_and_limits_are_closed():
    path=f'/v1/app/admin/demands/{D}/timeline'
    assert _query_values(method='GET',path=path,raw=b'limit=3')=={'limit':'3'}
    for query in (b'organization_id=123',b'limit=101',b'limit=1&limit=2',b'cursor=bad'):
        assert _query_values(method='GET',path=path,raw=query) is None

def test_review_fallback_keeps_reason_and_required_field_without_an_audit(demand,facts):
    facts['DEMAND']['demand_reviews']=[dict(id=S,reviewer_user_id=U,reviewed_at=T,decision='NEEDS_CHANGES',reason_codes=['SCOPE_UNCLEAR'],required_field_codes=['scope'])]
    result=project_timeline(demand,facts,{'events':[]},T)
    actual=result['events'][0]
    assert actual['details']['reason_code']=='SCOPE_UNCLEAR'
    assert '范围不清晰' in actual['summary'] and '范围与交付（scope）' in actual['summary']


def test_event_paging_invalidates_a_changed_cross_domain_snapshot(principal,demand,facts):
    from contextlib import contextmanager
    from datetime import datetime,timezone
    class Result:
        def __init__(self,value): self.value=value
        def fetchone(self): return (self.value,)
    class Connection:
        def execute(self,sql,params=None):
            if 'list_admin_demands' in sql: return Result([demand])
            for source,schema in (('DEMAND','demand'),('MATCHING','matching'),('TRUST','trust')):
                if schema+'_api.admin_demand_facts' in sql: return Result(facts[source])
            if 'read_admin_demand_audit' in sql:
                return Result({'events':[event(),event(event_id=O,occurred_at='2026-09-04T00:00:01Z')]})
            return Result(datetime(2026,9,4,tzinfo=timezone.utc))
    class Service(PsycopgAdminDemandTimelineService):
        @contextmanager
        def _read(self,*args): yield Connection()
    service=Service(connections=None,cursor_codec=AdminDemandCursorCodec(b'k'*32))
    page=service.get_timeline(principal=principal,demand_id=D,limit=1)
    assert page['has_more']
    next_page=service.get_timeline(principal=principal,demand_id=D,limit=1,cursor=page['next_cursor'])
    assert not next_page['has_more'] and next_page['events'][0]['event_id']==O
    facts['MATCHING']['invitations']=[dict(id=R,creator_user_id=R,created_by_user_id=U)]
    with pytest.raises(EditorServiceError) as caught:
        service.get_timeline(principal=principal,demand_id=D,limit=1,cursor=page['next_cursor'])
    assert caught.value.status==409 and caught.value.code=='TIMELINE_CHANGED'

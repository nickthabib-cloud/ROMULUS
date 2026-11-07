"""Authenticated catalog browsing and exports."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select

from romulus.catalog.browser import CatalogBrowser, applicability, known_families, load_tags
from romulus.catalog.models import COVERAGE_STRENGTH_LEGEND
from romulus.store import schema as t


def catalog_user(repo, need, request, *, lead=False):
    user = need(request)
    with repo.engine.connect() as c:
        account = c.execute(select(t.user.c.role, t.user.c.disabled).where(
            t.user.c.username == user.get('u'))).first()
    if (account is None or account.disabled or account.role not in {'analyst', 'lead'}
            or lead and (account.role != 'lead' or user.get('r') != 'lead')):
        raise HTTPException(403, 'An active lead account is required' if lead else 'An active account is required')
    return {**user, 'r': account.role}


def register_catalog_routes(app, repo, need, page):
    def filters(request):
        result = {key: request.query_params.get(key, '') for key in (
            'q', 'family', 'tactic', 'technique', 'lane', 'assurance', 'applicability', 'source', 'never_fired')}
        if any(len(value) > 256 for value in result.values()):
            raise HTTPException(400, 'Catalog filter is too long')
        return result

    @app.get('/catalog', response_class=HTMLResponse)
    def catalog(request: Request):
        user = catalog_user(repo, need, request)
        browser = CatalogBrowser(repo)
        selected = filters(request)
        after = request.query_params.get('after', '')
        if len(after) > 256:
            raise HTTPException(400, 'Invalid page cursor')
        rows, cursor = browser.rules(selected, after=after)
        families = known_families()
        return page(request, 'catalog.html', user, rows=rows, filters=selected, families=families,
                    legend=COVERAGE_STRENGTH_LEGEND, deleted=browser.deleted_hunts(),
                    next_url='/catalog?' + urlencode({**selected, 'after': cursor}) if cursor else None,
                    export_query=urlencode(selected), last_n=10)

    @app.get('/catalog/export')
    def export(request: Request):
        catalog_user(repo, need, request)
        format = request.query_params.get('format', 'csv')
        if format not in {'csv', 'md'}:
            raise HTTPException(400, 'Unsupported export format')
        return StreamingResponse(CatalogBrowser(repo).export(filters(request), format),
            media_type='text/csv' if format == 'csv' else 'text/markdown',
            headers={'Content-Disposition': f'attachment; filename="catalog.{format}"'})

    @app.get('/catalog/attack', response_class=HTMLResponse)
    def attack(request: Request, domain: str = 'enterprise', after: str = ''):
        user = catalog_user(repo, need, request)
        if domain not in {'enterprise', 'ics'} or len(after) > 128:
            raise HTTPException(400, 'Invalid ATT&CK domain or cursor')
        browser = CatalogBrowser(repo)
        catalog = browser.catalog(domain)
        # Local rules participate in the same strength accounting as shipped rules.
        from romulus.catalog.build import build_catalog
        from romulus.detect.registry import ALL_PLAYBOOKS
        sigma = [row for row in browser.base_rules() if row['source'] == 'Sigma']
        if sigma:
            from romulus.content.sigma_store import SigmaRules
            from romulus.detect.sigma import SigmaRule
            catalog = build_catalog(domain=domain, playbooks=[
                *ALL_PLAYBOOKS, *(SigmaRule(row) for row in SigmaRules(repo).iter_rules() if row['status'] == 'active')])
        rows = [row for row in catalog.coverage_by_technique if row.technique.id > after]
        return page(request, 'catalog_attack.html', user, domain=domain, rows=rows[:50],
                    legend=COVERAGE_STRENGTH_LEGEND, tactics=catalog.tactics,
                    next_url='/catalog/attack?' + urlencode({'domain': domain, 'after': rows[49].technique.id})
                    if len(rows) > 50 else None)

    @app.get('/catalog/tags/{kind}', response_class=HTMLResponse)
    def tags(request: Request, kind: str, after: int = 0):
        user = catalog_user(repo, need, request)
        if kind not in {'tools', 'lotl', 'themes'} or after < 0:
            raise HTTPException(404)
        rows = load_tags()[kind]
        return page(request, 'catalog_tags.html', user, kind=kind, rows=rows[after:after + 50],
                    next_url=f'/catalog/tags/{kind}?after={after + 50}' if len(rows) > after + 50 else None)

    @app.get('/catalog/families', response_class=HTMLResponse)
    def families(request: Request, after: str = ''):
        user = catalog_user(repo, need, request)
        browser = CatalogBrowser(repo)
        rules = browser.base_rules()
        names = [family for family in known_families() if family > after]
        rows = []
        for name in names[:50]:
            members = [row for row in rules if name in row['families']]
            fields = sorted({field for row in members for field in (
                *row['required_fields'], *row['required_by_family'].get(name, ()))})
            rows.append({'name': name, 'rules': members[:50], 'rule_count': len(members), 'fields': fields,
                         'sources': applicability({'families': [name], 'required_fields': [],
                                                   'required_by_family': {}}, browser.profiles())})
        return page(request, 'catalog_families.html', user, rows=rows,
                    next_url='/catalog/families?' + urlencode({'after': names[49]}) if len(names) > 50 else None)

    @app.get('/catalog/rules/{rule_id}', response_class=HTMLResponse)
    def detail(request: Request, rule_id: str):
        user = catalog_user(repo, need, request)
        if len(rule_id) > 256:
            raise HTTPException(404)
        browser = CatalogBrowser(repo)
        try:
            rule = browser.detail(rule_id)
        except KeyError:
            raise HTTPException(404, 'Rule not found') from None
        tags = {kind: [row for row in rows if rule_id in row['rules']] for kind, rows in load_tags().items()}
        return page(request, 'catalog_rule.html', user, rule=rule, tags=tags,
                    deleted=browser.deleted_hunts(), last_n=10)

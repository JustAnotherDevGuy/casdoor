#!/usr/bin/env python3
"""End-to-end test of cross-organization application grants against a running Casdoor.

Uses only synthetic identities from seed.json and the standard library. Every request goes
through the real HTTP stack: routing, the authz filter, the record filter, the login controller,
the OAuth endpoints and the bearer-token filter.

    CASDOOR_URL=http://127.0.0.1:18000 ./run.py
"""

import base64
import hashlib
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("CASDOOR_URL", "http://127.0.0.1:18000").rstrip("/")
ADMIN_PASSWORD = os.environ.get("CASDOOR_ADMIN_PASSWORD", "")
PASSWORD = "E2e-Synthetic-Pass-1"
REDIRECT = "https://rp.example.test/callback"
CLIENTS = {
    "pve-like": ("e2e-client-pve", "e2e-secret-pve"),
    "grafana-like": ("e2e-client-grafana", "e2e-secret-grafana"),
}

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(("PASS " if condition else "FAIL ") + name + ("" if condition or not detail else f"  -- {detail}"))


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, method, path, query=None, body=None, form=None, headers=None):
        url = BASE + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None
        hdrs = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=30) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as err:
            status, raw = err.code, err.read()
        try:
            return status, json.loads(raw or b"null")
        except ValueError:
            return status, raw.decode(errors="replace")

    def login(self, application, organization, username, password):
        status, res = self.request("POST", "/api/login", body={
            "application": application, "organization": organization, "username": username,
            "password": password, "type": "login", "signinMethod": "Password", "autoSignin": False,
        })
        return res


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def authorize(application, username, organization="resource-org"):
    """The code flow exactly as the sign-in page of the application runs it."""
    client_id, _ = CLIENTS[application]
    verifier, challenge = pkce()
    state, nonce = secrets.token_hex(8), secrets.token_hex(8)
    browser = Client()
    oauth = {"clientId": client_id, "responseType": "code", "redirectUri": REDIRECT, "scope": "openid profile email offline_access",
             "state": state, "nonce": nonce, "code_challenge_method": "S256", "code_challenge": challenge}
    status, app_login = browser.request("GET", "/api/get-app-login", query={**oauth, "type": "code"})
    if app_login.get("status") != "ok":
        return {"error": app_login.get("msg")}
    status, res = browser.request("POST", "/api/login", query=oauth, body={
        "application": application, "organization": organization, "username": username, "password": PASSWORD,
        "type": "code", "signinMethod": "Password", "autoSignin": False,
    })
    if res.get("status") != "ok":
        return {"error": res.get("msg")}
    return {"code": res["data"], "verifier": verifier, "nonce": nonce, "state": state}


def exchange(application, flow, verifier=None):
    client_id, client_secret = CLIENTS[application]
    status, res = Client().request("POST", "/api/login/oauth/access_token", form={
        "grant_type": "authorization_code", "client_id": client_id, "client_secret": client_secret,
        "code": flow["code"], "code_verifier": verifier or flow["verifier"], "redirect_uri": REDIRECT,
    })
    return res


def refresh(application, refresh_token):
    client_id, client_secret = CLIENTS[application]
    status, res = Client().request("POST", "/api/login/oauth/refresh_token", form={
        "grant_type": "refresh_token", "client_id": client_id, "client_secret": client_secret,
        "refresh_token": refresh_token, "scope": "openid profile email offline_access",
    })
    return res


def userinfo(access_token):
    return Client().request("GET", "/api/userinfo", headers={"Authorization": "Bearer " + access_token})


def roles_section(global_admin, resource_admin, partner_admin):
    """Application roles: what a grant may add to one application's claims, and who may set it."""
    pve_admin = {"name": "pve-admin", "displayName": "PVE administrators", "isPrivileged": True, "groups": ["resource-org/pve-admins"], "roles": [], "claims": []}
    reader = {"name": "reader", "groups": [], "roles": [], "claims": [{"name": "app_role", "value": "Reader", "type": "String", "category": "Static Value"}]}
    body = {"owner": "resource-org", "name": "pve-like", "application": "pve-like", "appRoles": [pve_admin, reader]}

    _, res = partner_admin.request("POST", "/api/update-application-roles", body=body)
    check("roles: partner-org admin can't define roles of a foreign application", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/update-application-roles", body={**body, "appRoles": [{**pve_admin, "groups": ["partner-org/pve-admins"]}]})
    check("roles: a role can't project a group of another organization", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/update-application-roles", body={**body, "appRoles": [{**reader, "claims": [{"name": "sub", "value": "x", "type": "String"}]}]})
    check("roles: a role can't set the sub claim", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/update-application-roles", body=body)
    check("roles: resource-org admin defines the application's roles", res.get("status") == "ok", res)
    _, app = Client().request("GET", "/api/get-application", query={"id": "admin/pve-like"})
    check("roles: role definitions are hidden from anonymous callers", not ((app or {}).get("data") or {}).get("appRoles"), (app or {}).get("data", {}).get("appRoles") if isinstance(app, dict) else app)

    _, res = resource_admin.request("POST", "/api/add-application-grant", body={
        "owner": "resource-org", "application": "pve-like", "principalType": "User", "principal": "partner-org/carol", "roles": ["undefined"]})
    check("roles: a grant can't assign an undefined role", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/add-application-grant", body={
        "owner": "resource-org", "application": "pve-like", "principalType": "User", "principal": "partner-org/carol", "roles": ["pve-admin"], "description": "e2e roles"})
    check("roles: grant with the privileged role", res.get("status") == "ok", res)
    _, grants = resource_admin.request("GET", "/api/get-application-grants", query={"owner": "resource-org", "application": "pve-like"})
    grant = next((g for g in grants.get("data") or [] if g["principal"] == "partner-org/carol"), None)
    check("roles: the grant lists its roles", grant and grant.get("roles") == ["pve-admin"], grant)

    flow = authorize("pve-like", "carol")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("roles: projected Proxmox group in the token", "pve-admins" in (claims.get("groups") or []), claims.get("groups"))
    check("roles: own group still qualified next to it", "partner-org/pve-admins" in (claims.get("groups") or []), claims.get("groups"))
    check("roles: identity claims unchanged", claims.get("name") == "carol@partner-org", claims.get("name"))
    status, info = userinfo(tokens.get("access_token", ""))
    check("roles: projected group in userinfo", status == 200 and "pve-admins" in (info.get("groups") or []), info)

    _, res = partner_admin.request("POST", "/api/update-application-grant", body={"owner": "resource-org", "name": grant["name"] if grant else "", "roles": ["pve-admin", "reader"]})
    check("roles: partner-org admin can't change the grant", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/update-application-grant", body={"owner": "resource-org", "name": grant["name"] if grant else "", "application": "pve-like", "roles": ["reader"], "principal": "partner-org/dave"})
    check("roles: resource-org admin changes the grant's roles", res.get("status") == "ok", res)
    status, info = userinfo(tokens.get("access_token", ""))
    check("roles: userinfo drops the removed role at once", status == 200 and "pve-admins" not in (info.get("groups") or []) and info.get("app_role") == "Reader", info)
    _, grants = resource_admin.request("GET", "/api/get-application-grants", query={"owner": "resource-org", "application": "pve-like"})
    edited = next((g for g in grants.get("data") or [] if g["name"] == (grant or {}).get("name")), {})
    check("roles: the edit can't move the grant to another principal", edited.get("principal") == "partner-org/carol" and edited.get("updatedBy") == "resource-org/resource-admin", edited)

    _, res = resource_admin.request("POST", "/api/update-application-roles", body={**body, "appRoles": [pve_admin]})
    check("roles: a role still assigned can't be removed", res.get("status") != "ok", res)

    _, preview = resource_admin.request("GET", "/api/get-application-access-preview", query={"owner": "resource-org", "application": "pve-like", "user": "partner-org/carol"})
    data = preview.get("data") or {}
    check("roles: preview explains the grant", data.get("access") == "Grant" and [r["name"] for r in data["entitlements"]["roles"]] == ["reader"], data)
    _, preview = resource_admin.request("GET", "/api/get-application-access-preview", query={"owner": "resource-org", "application": "pve-like", "user": "partner-org/dave", "roles": "pve-admin"})
    data = preview.get("data") or {}
    check("roles: draft preview hides the memberships of an ungranted user", data.get("access") == "Denied" and data.get("ownGroups") == [] and data.get("groups") == ["pve-admins"] and data.get("privileged"), data)
    _, preview = partner_admin.request("GET", "/api/get-application-access-preview", query={"owner": "resource-org", "application": "pve-like", "user": "resource-org/internal-bob"})
    check("roles: partner-org admin can't explain access to a foreign application", preview.get("status") != "ok", preview)

    check("roles: dave (no grant) still denied", "error" in authorize("pve-like", "dave"))
    flow = authorize("pve-like", "internal-bob")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("roles: internal user's claims unchanged by roles", claims.get("name") == "internal-bob" and claims.get("groups") == ["pve-admins"] and "app_role" not in claims, claims)


def main():
    status, health = Client().request("GET", "/api/health")
    check("server healthy", status == 200, health)

    global_admin = Client()
    check("global admin signs in", global_admin.login("app-built-in", "built-in", "admin", ADMIN_PASSWORD).get("status") == "ok")
    resource_admin = Client()
    check("resource-org admin signs in", resource_admin.login("pve-like", "resource-org", "resource-admin", PASSWORD).get("status") == "ok")
    partner_admin = Client()
    check("partner-org admin signs in", partner_admin.login("partner-portal", "partner-org", "partner-admin", PASSWORD).get("status") == "ok")
    carol_session = Client()
    check("carol signs in to her own organization", carol_session.login("partner-portal", "partner-org", "carol", PASSWORD).get("status") == "ok")

    # B: denied by default
    flow = authorize("pve-like", "carol")
    check("B: external user without a grant gets no code", "error" in flow, flow)

    # unauthorized grant management
    grant_body = {"owner": "resource-org", "application": "pve-like", "principalType": "User", "principal": "partner-org/carol"}
    _, res = partner_admin.request("POST", "/api/add-application-grant", body=grant_body)
    check("partner-org admin can't grant itself the foreign application", res.get("status") != "ok", res)
    _, res = partner_admin.request("POST", "/api/add-application-grant", body={**grant_body, "owner": "partner-org"})
    check("partner-org admin can't grant by claiming the application's organization", res.get("status") != "ok", res)
    _, res = carol_session.request("POST", "/api/add-application-grant", body=grant_body)
    check("regular user can't create a grant", res.get("status") != "ok", res)
    _, res = carol_session.request("GET", "/api/get-application-grants", query={"owner": "resource-org", "application": "pve-like"})
    check("regular user can't list grants", res.get("status") != "ok", res)
    _, res = partner_admin.request("GET", "/api/get-application-grant-principals", query={
        "owner": "partner-org", "application": "pve-like", "principalType": "User", "organization": "resource-org", "query": "b"})
    check("partner-org admin can't search principals for a foreign application", res.get("status") != "ok", res)

    # principal search scope
    _, res = resource_admin.request("GET", "/api/get-application-grant-principals", query={
        "owner": "resource-org", "application": "pve-like", "principalType": "User", "organization": "partner-org", "query": "car"})
    check("org admin search does not list another organization by substring", res.get("status") == "ok" and res["data"] == [], res)
    _, res = resource_admin.request("GET", "/api/get-application-grant-principals", query={
        "owner": "resource-org", "application": "pve-like", "principalType": "User", "organization": "partner-org", "query": "carol"})
    check("org admin finds the exactly named principal", res.get("status") == "ok" and [p["id"] for p in res["data"]] == ["partner-org/carol"], res)
    check("principal search returns only id and display name", res.get("status") == "ok" and set(res["data"][0].keys()) == {"type", "id", "displayName"}, res)
    _, res = global_admin.request("GET", "/api/get-application-grant-principals", query={
        "owner": "resource-org", "application": "pve-like", "principalType": "User", "organization": "partner-org", "query": "car"})
    check("global admin searches by substring", res.get("status") == "ok" and len(res["data"]) == 1, res)

    # A: grant and sign in
    _, res = resource_admin.request("POST", "/api/add-application-grant", body={**grant_body, "description": "e2e"})
    check("A: resource-org admin grants carol access to pve-like", res.get("status") == "ok" and res.get("data") == "Affected", res)
    _, res = resource_admin.request("POST", "/api/add-application-grant", body=grant_body)
    check("duplicate grant refused", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/add-application-grant", body={**grant_body, "principal": "resource-org/internal-bob"})
    check("grant to the application's own organization refused", res.get("status") != "ok", res)
    _, grants = resource_admin.request("GET", "/api/get-application-grants", query={"owner": "resource-org", "application": "pve-like"})
    carol_grant = next((g for g in grants.get("data") or [] if g["principal"] == "partner-org/carol"), None)
    check("grant lists who created it and when", carol_grant and carol_grant["createdBy"] == "resource-org/resource-admin" and carol_grant["createdTime"], grants)

    flow = authorize("pve-like", "carol")
    check("A: carol gets a code on the unchanged pve-like client", "code" in flow, flow)
    if "code" in flow:
        res = exchange("pve-like", flow, verifier="wrong-verifier-" + secrets.token_hex(16))
        check("PKCE verifier still enforced", "access_token" not in res, res)
        flow = authorize("pve-like", "carol")
        tokens = exchange("pve-like", flow)
        check("A: code exchange with PKCE and client secret", "access_token" in tokens, tokens)
        claims = jwt_claims(tokens["access_token"])
        id_claims = jwt_claims(tokens["id_token"])
        check("A: qualified name claim", claims.get("name") == "carol@partner-org", claims.get("name"))
        check("A: foreign group qualified, no collision with resource-org/pve-admins", claims.get("groups") == ["partner-org/pve-admins"], claims.get("groups"))
        check("A: audience is the unchanged client ID", claims.get("aud") == ["e2e-client-pve"], claims.get("aud"))
        check("nonce preserved in the ID token", id_claims.get("nonce") == flow["nonce"], id_claims.get("nonce"))
        status, info = userinfo(tokens["access_token"])
        check("A: userinfo preferred_username qualified", status == 200 and info.get("preferred_username") == "carol@partner-org", info)
        check("A: userinfo groups qualified", info.get("groups") == ["partner-org/pve-admins"], info)
        pve_access_token = tokens["access_token"]
        alt = authorize("pve-like", "partner-org/carol")
        check("explicit organization/username sign-in", "code" in alt, alt)
        alt = authorize("pve-like", "carol@partner.example.test")
        check("email sign-in resolves the granted user", "code" in alt, alt)

    # B: still denied for others
    check("B: dave (same org, no grant) denied", "error" in authorize("pve-like", "dave"))
    check("B: frank (other org) denied", "error" in authorize("pve-like", "frank"))
    check("B: partner-org admin denied (org admins can't self-authorize)", "error" in authorize("pve-like", "partner-admin"))

    # D: isolation
    check("D: pve-like grant does not open grafana-like", "error" in authorize("grafana-like", "carol"))

    # E: internal users unchanged
    flow = authorize("pve-like", "internal-bob")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("E: internal user claims unchanged", claims.get("name") == "internal-bob" and claims.get("groups") == ["pve-admins"], claims)
    flow = authorize("grafana-like", "resource-admin")
    tokens = exchange("grafana-like", flow) if "code" in flow else {}
    check("E: internal admin signs in to grafana-like", "access_token" in tokens, tokens)
    if "refresh_token" in tokens:
        check("E: internal refresh unchanged", "access_token" in refresh("grafana-like", tokens["refresh_token"]))

    # C: revocation of a user grant
    _, res = resource_admin.request("POST", "/api/delete-application-grant", body={"owner": "partner-org", "name": carol_grant["name"] if carol_grant else ""})
    check("revocation by claiming another owner refused", res.get("status") != "ok", res)
    _, res = partner_admin.request("POST", "/api/delete-application-grant", body={"owner": "resource-org", "name": carol_grant["name"] if carol_grant else ""})
    check("partner-org admin can't revoke the resource application's grant", res.get("status") != "ok", res)
    _, res = resource_admin.request("POST", "/api/delete-application-grant", body={"owner": "resource-org", "name": carol_grant["name"] if carol_grant else "", "application": "pve-like"})
    check("C: resource-org admin revokes carol's grant", res.get("status") == "ok" and res.get("data") == "Affected", res)
    check("C: no new code after revocation", "error" in authorize("pve-like", "carol"))
    if "pve_access_token" in locals():
        status, info = userinfo(pve_access_token)
        check("C: userinfo with a token issued before revocation is rejected", status == 401, (status, info))

    # group grant, nested group, membership revocation, refresh
    _, res = resource_admin.request("POST", "/api/add-application-grant", body={
        "owner": "resource-org", "application": "grafana-like", "principalType": "Group", "principal": "partner-org/team"})
    check("group grant created", res.get("status") == "ok", res)
    flow = authorize("grafana-like", "erin")
    check("member of a child group of the granted group gets a code", "code" in flow, flow)
    tokens = exchange("grafana-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("home organization kept in the token", claims.get("owner") == "partner-org", claims.get("owner"))
    check("Path-format group of the granted user", claims.get("groups") == ["partner-org/team/contractors"], claims.get("groups"))
    if "refresh_token" in tokens:
        check("refresh with a valid group grant", "access_token" in refresh("grafana-like", tokens["refresh_token"]))
        _, erin = global_admin.request("GET", "/api/get-user", query={"id": "partner-org/erin"})
        erin = erin["data"]
        erin["groups"] = []
        _, res = global_admin.request("POST", "/api/update-user", query={"id": "partner-org/erin"}, body=erin)
        check("erin removed from the group by the partner organization", res.get("status") == "ok", res)
        res = refresh("grafana-like", tokens["refresh_token"])
        check("C: refresh refused after the group membership was removed", "access_token" not in res, res)
        status, info = userinfo(tokens["access_token"])
        check("C: userinfo refused after the group membership was removed", status == 401, (status, info))

    roles_section(global_admin, resource_admin, partner_admin)

    # audit trail
    _, records = global_admin.request("GET", "/api/get-records", query={"pageSize": 100, "p": 1, "field": "action", "value": "add-application-grant"})
    data = records.get("data") or []
    check("audit records for grant creation", any(r.get("action") == "add-application-grant" and r.get("user") == "resource-admin" for r in data), len(data))
    _, records = global_admin.request("GET", "/api/get-records", query={"pageSize": 100, "p": 1, "field": "action", "value": "delete-application-grant"})
    data = records.get("data") or []
    check("audit records for revocation", any(r.get("action") == "delete-application-grant" and r.get("organization") == "resource-org" for r in data), len(data))

    _, res = Client().request("GET", "/api/get-app-login", query={"type": "code", "clientId": "e2e-client-pve", "responseType": "code",
                                                                   "redirectUri": "https://attacker.example.test/cb", "scope": "openid", "state": "x"})
    check("unregistered redirect URI refused", res.get("status") != "ok", res)

    status, discovery = Client().request("GET", "/.well-known/openid-configuration")
    check("discovery document unchanged", status == 200 and discovery.get("issuer"), discovery)

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def baseline():
    """What must hold on any version, including a stock Casdoor without grants and after a rollback."""
    status, health = Client().request("GET", "/api/health")
    check("server healthy", status == 200, health)
    flow = authorize("pve-like", "internal-bob")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("internal user signs in with unchanged claims", claims.get("name") == "internal-bob" and claims.get("groups") == ["pve-admins"], claims or flow)
    flow = authorize("grafana-like", "resource-admin")
    tokens = exchange("grafana-like", flow) if "code" in flow else {}
    check("internal admin signs in to grafana-like", "access_token" in tokens, tokens or flow)
    if "refresh_token" in tokens:
        check("internal refresh works", "access_token" in refresh("grafana-like", tokens["refresh_token"]))
    check("partner user carol is denied (fail closed without grant support)", "error" in authorize("pve-like", "carol"))
    check("partner user dave is denied", "error" in authorize("pve-like", "dave"))
    status, discovery = Client().request("GET", "/.well-known/openid-configuration")
    check("discovery document served", status == 200 and discovery.get("issuer"), discovery)
    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} baseline checks passed")
    return 1 if failed else 0


def rollback_to_grants():
    """After rolling an upgraded database back to a build with grants but without application roles:
    grants still allow the sign-in, nothing is projected any more (fail closed), internal users are unchanged."""
    status, _ = Client().request("GET", "/api/health")
    check("server healthy", status == 200)
    flow = authorize("pve-like", "internal-bob")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("internal user unchanged", claims.get("name") == "internal-bob" and claims.get("groups") == ["pve-admins"], claims or flow)
    flow = authorize("pve-like", "carol")
    tokens = exchange("pve-like", flow) if "code" in flow else {}
    claims = jwt_claims(tokens["access_token"]) if "access_token" in tokens else {}
    check("granted user still signs in", claims.get("name") == "carol@partner-org", claims or flow)
    check("no projected group or claim without application role support", "pve-admins" not in (claims.get("groups") or []) and "app_role" not in claims, claims)
    check("ungranted user denied", "error" in authorize("pve-like", "dave"))
    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} rollback checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    if "--baseline" in sys.argv:
        sys.exit(baseline())
    if "--rollback-to-grants" in sys.argv:
        sys.exit(rollback_to_grants())
    sys.exit(main())

"""Generate local secrets and a Keycloak realm; never prints credential values."""
import argparse
import json
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit


def realm(config):
    base = config["PUBLIC_BASE_URL"].rstrip("/")
    roles_mapper = {"name": "realm-roles", "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-realm-role-mapper", "config": {
                        "claim.name": "realm_access.roles", "jsonType.label": "String", "multivalued": "true",
                        "access.token.claim": "true", "id.token.claim": "true"}}

    def audience(value):
        return {"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": value, "access.token.claim": "true", "id.token.claim": "false"}}

    scopes = [{"name": name, "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"},
               "protocolMappers": []} for name in ["vul.read", "vul.submit", "vul.deliver"]]
    scopes.append({"name": "basic", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "false"},
                   "protocolMappers": [{"name": "subject", "protocol": "openid-connect",
                                        "protocolMapper": "oidc-sub-mapper",
                                        "config": {"access.token.claim": "true", "lightweight.claim": "true",
                                                   "introspection.token.claim": "true"}}]})
    return {"realm": "vul", "enabled": True, "sslRequired": "external", "registrationAllowed": False,
            "requiredActions": [{"alias": "VERIFY_PROFILE", "name": "Verify Profile", "providerId": "VERIFY_PROFILE",
                                 "enabled": False, "defaultAction": False, "priority": 50}],
            "bruteForceProtected": True, "accessTokenLifespan": 300, "revokeRefreshToken": True,
            "refreshTokenMaxReuse": 1, "ssoSessionIdleTimeout": 86400, "ssoSessionMaxLifespan": 2592000,
            "offlineSessionIdleTimeout": 2592000, "roles": {"realm": [{"name": "vul-admin"}]},
            "clientScopes": scopes,
            "clients": [
                {"clientId": "vul-mcp", "name": "漏洞情报 MCP", "publicClient": True,
                 "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                 "redirectUris": [config["MCP_REDIRECT_URI"]], "webOrigins": [], "fullScopeAllowed": True,
                 "attributes": {"pkce.code.challenge.method": "S256", "use.refresh.tokens": "true"},
                 "defaultClientScopes": ["basic", "vul.read"],
                 "optionalClientScopes": ["vul.submit", "vul.deliver", "offline_access"],
                 "protocolMappers": [roles_mapper, audience(base + "/mcp")]},
                {"clientId": "vul-web", "name": "漏洞情报管理网页", "publicClient": False,
                 "secret": config["WEB_CLIENT_SECRET"], "standardFlowEnabled": True,
                 "directAccessGrantsEnabled": False, "fullScopeAllowed": True,
                 "redirectUris": [base + "/admin/callback"], "webOrigins": [base],
                 "attributes": {"pkce.code.challenge.method": "S256"},
                 "defaultClientScopes": ["basic"], "protocolMappers": [roles_mapper, audience("vul-web")]},
            ], "users": [{"username": config["ADMIN_USERNAME"], "enabled": True,
                          "realmRoles": ["vul-admin", "offline_access"],
                          "credentials": [{"type": "password", "value": config["ADMIN_PASSWORD"], "temporary": False}]}]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=".env")
    parser.add_argument("--realm", default="secrets/realm.json")
    args = parser.parse_args()
    path = Path(args.env)
    if not path.exists():
        raise SystemExit("先复制 .env.example 到 .env 并填写 MCP_REDIRECT_URI")
    config = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip().strip('"').strip("'")
    redirect = urlsplit(config.get("MCP_REDIRECT_URI", ""))
    if redirect.scheme != "https" or not redirect.hostname or redirect.query or redirect.fragment:
        raise SystemExit("MCP_REDIRECT_URI 必须是连接界面提供的准确 HTTPS 回调，不使用通配符")
    if Path(args.realm).exists():
        raise SystemExit("realm 文件已存在，拒绝覆盖。已有数据库请通过 Keycloak 管理界面修改，不重新导入。")
    generated = {}
    for key in ["POSTGRES_PASSWORD", "VUL_DB_PASSWORD", "KEYCLOAK_DB_PASSWORD",
                "KEYCLOAK_BOOTSTRAP_PASSWORD", "WEB_CLIENT_SECRET", "ADMIN_PASSWORD", "WEBHOOK_SECRET"]:
        if not config.get(key):
            config[key] = secrets.token_urlsafe(32)
            generated[key] = config[key]
    # Preserve caller-provided dotenv quoting, especially SMTP passwords containing '$'.
    output_lines = []
    for line in lines:
        key = line.split("=", 1)[0].strip()
        output_lines.append(f"{key}='{generated.pop(key)}'" if key in generated else line)
    output_lines.extend(f"{key}='{value}'" for key, value in generated.items())
    path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    output = Path(args.realm)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(json.dumps(realm(config), ensure_ascii=False, indent=2), encoding="utf-8")
    output.chmod(0o600)
    if os.name == "posix" and os.geteuid() == 0:
        os.chown(output, 1000, 0)  # Keycloak image runs as UID 1000; bind mount must be readable.
    print("已生成 .env 和 secrets/realm.json；请仅在服务器本地读取管理员密码。未输出任何凭据。")


if __name__ == "__main__":
    main()

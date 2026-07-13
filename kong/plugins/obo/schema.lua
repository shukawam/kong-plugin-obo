local typedefs = require "kong.db.schema.typedefs"

-- プラグイン名。ディレクトリ名（kong/plugins/obo）と一致している必要がある
local PLUGIN_NAME = "obo"

-- tenant_id は URL パス（メタデータ / トークンエンドポイント / issuer）にそのまま連結される。
-- 本プラグインは単一テナント前提のため、ドメイン名（contoso.onmicrosoft.com）や
-- common / organizations ではなく GUID のみを許可する。ドメイン名を許可すると、
-- メタデータが返す正規化済み GUID issuer との突き合わせが別途必要になり複雑化する
-- （docs/obo/05「Validate the issuer」）。8-4-4-4-12 桁の 16 進（大文字小文字問わず）。
local TENANT_ID_GUID_PATTERN =
  "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- consumer 単位では設定できない（認証系プラグインの typical な制約）
    { consumer = typedefs.no_consumer },
    -- HTTP/HTTPS のリクエストのみ対象
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Entra ID のテナント ID（GUID）。トークンエンドポイントと issuer の導出に使う。
          -- 単一テナント前提のため GUID 形式のみ許可する（match で検証）。
          -- 大文字の GUID も受理するが、URL / issuer の導出時に util.build_tenant_url が
          -- 小文字へ正規化する（Entra のメタデータ issuer は小文字 GUID で返るため）
          { tenant_id = { type = "string", required = true,
              match = TENANT_ID_GUID_PATTERN } },

          -- middle-tier（このゲートウェイ）として登録したアプリのクライアント ID
          { client_id = { type = "string", required = true } },

          -- Entra ID へのクライアント認証方式（docs/obo/02, 04 参照）
          { client_auth_method = { type = "string", required = true,
              default = "client_secret",
              one_of = { "client_secret", "private_key_jwt" } } },

          -- client_secret 方式のシークレット。
          -- referenceable: Vault 参照（{vault://...}）を許可
          -- encrypted: Kong EE ではデータベース上で暗号化される（OSS では無視されるが害はない）
          { client_secret = { type = "string", referenceable = true, encrypted = true } },

          -- private_key_jwt 方式の署名用秘密鍵（PEM 形式）
          { private_key = { type = "string", referenceable = true, encrypted = true } },

          -- 証明書 DER の SHA-256 サムプリント（Base64url）。client assertion の x5t#S256 ヘッダーに入れる
          { certificate_thumbprint = { type = "string" } },

          -- 交換後トークンに要求するスコープ（スペース区切りで scope パラメータに連結される）
          -- 注意: .default と他の委任スコープの併用は AADSTS70011 になる（docs/obo/06）
          { scopes = { type = "array", required = true,
              elements = { type = "string" }, len_min = 1 } },

          -- 受信トークンの aud クレームの期待値（= このアプリの client_id など）
          { audience = { type = "string", required = true } },

          -- OpenID メタデータの issuer に対する任意のピン（追加の防御）。
          -- 設定時、メタデータの issuer がこの値と完全一致しない場合は拒否する（fail-close）。
          -- 受信トークンの iss は常に「検証済みメタデータの issuer」と照合されるため、
          -- この値で iss の期待値を別の値に差し替えることはできない
          { issuer = { type = "string" } },

          -- 受信トークンに要求する委任スコープ（scp クレーム）のリスト。
          -- 設定すると、scp にこれら全てを含まないトークンを 403（insufficient_scope）で拒否する。
          -- 未設定なら scp の検査は行わない（後方互換）。認可を別プラグイン等に委ねる運用も可能。
          -- scp は「スペース区切りのスコープ文字列」で、ユーザートークンにのみ含まれる
          --（docs/obo/05 / Microsoft "Access token claims reference" の scp 行）。
          -- 要素に空白を含む値は設定ミス（scp のスペース区切りでは絶対に一致しない）なので、
          -- Lua パターン ^%S+$（空白以外の文字が 1 文字以上）で弾いて早期に気づけるようにする。
          -- len_min = 1: 「省略（未設定）は許可、明示的な空配列は拒否」。値の入れ忘れで
          -- 空配列だけが残ると認可が黙ってスキップされる（fail-open）のを設定時に検出する
          { required_scopes = { type = "array", len_min = 1,
              elements = { type = "string", match = "^%S+$" } } },

          -- 受信トークンに要求するアプリロール（roles クレーム）のリスト。
          -- 設定すると、roles にこれら全てを含まないトークンを 403 で拒否する。未設定なら検査しない。
          -- roles は「文字列の配列」で、app-only トークンにもユーザーの割当ロールにも使われるため、
          -- 「ユーザートークンかどうか」の判定には使わない（docs/obo/05 の roles 行）。
          -- このため required_roles のみ設定時も scope_validator が非空の scp の存在を要求する。
          -- len_min = 1: required_scopes と同じく、明示的な空配列（fail-open のもと）を拒否する。
          -- match = "^%S+$": roles クレームに入る app role の「Value」は空白を含められない
          -- （"The value can't contain spaces."
          --   https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps
          --   の Value 行。空白を含められるのは Display name のみ）ため、
          -- 空白入りの要素は絶対に一致しない設定ミスとして schema で弾く
          { required_roles = { type = "array", len_min = 1,
              elements = { type = "string", match = "^%S+$" } } },

          -- Entra ID のベース URL。通常は変更不要（統合テストではモック IdP に向ける）
          { identity_base_url = typedefs.url { required = true,
              default = "https://login.microsoftonline.com" } },

          -- 交換済みトークンをキャッシュするか
          { token_cache_enabled = { type = "boolean", required = true, default = true } },

          -- キャッシュ TTL を expires_in から何秒差し引くか（期限ギリギリのトークンを使わないための余裕）
          { cache_ttl_margin = { type = "integer", required = true, default = 30, gt = -1 } },

          -- Entra ID への HTTP タイムアウト（ミリ秒）
          { http_timeout = { type = "integer", required = true, default = 10000, gt = 0 } },

          -- Entra ID への接続で TLS 証明書を検証するか（本番では必ず true）
          { ssl_verify = { type = "boolean", required = true, default = true } },
        },
        entity_checks = {
          -- 認証方式に応じた条件付き必須チェック
          { conditional = {
              if_field = "client_auth_method", if_match = { eq = "client_secret" },
              then_field = "client_secret", then_match = { required = true },
          } },
          { conditional = {
              if_field = "client_auth_method", if_match = { eq = "private_key_jwt" },
              then_field = "private_key", then_match = { required = true },
          } },
          { conditional = {
              if_field = "client_auth_method", if_match = { eq = "private_key_jwt" },
              then_field = "certificate_thumbprint", then_match = { required = true },
          } },
        },
      },
    },
  },
}

return schema

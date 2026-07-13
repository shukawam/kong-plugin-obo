local typedefs = require "kong.db.schema.typedefs"

-- プラグイン名。ディレクトリ名（kong/plugins/obo）と一致している必要がある
local PLUGIN_NAME = "obo"

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
          -- Entra ID のテナント ID（GUID）。トークンエンドポイントと issuer の導出に使う
          { tenant_id = { type = "string", required = true } },

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

          -- 受信トークンの iss の期待値。省略時は identity_base_url と tenant_id から導出
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

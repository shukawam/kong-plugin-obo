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
          -- 設定フィールドは Task 2 で追加する
        },
      },
    },
  },
}

return schema

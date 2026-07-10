-- obo プラグインのハンドラー
-- Kong はリクエスト処理の各フェーズ（access など）でこのテーブルのメソッドを呼び出す。
-- ロジックは責務別モジュールに分割し、このファイルはオーケストレーションに徹する（CLAUDE.md 参照）。

local plugin = {
  -- PRIORITY はプラグインの実行順序を決める（大きいほど先に実行される）
  PRIORITY = 1000,
  -- プラグインのバージョン（rockspec のバージョンと一致させる）
  VERSION = "0.1.0",
}

-- access フェーズ: upstream にリクエストが送られる前に実行される
-- ここで受信トークンの検証と OBO 交換を行う（Task 8 で実装）
function plugin:access(conf)  -- luacheck: ignore 212
end

return plugin

# obo プラグイン入り Kong Gateway（ローカル検証用）
# ビルド: docker build -t kong-obo .
FROM kong:3.9

# luarocks make はイメージ内の LuaRocks ツリーへ書き込むため root で実行する
USER root

# リポジトリ一式をコピーして rockspec 経由でインストールする
# （rockspec の build.modules が唯一のインストール定義。記載漏れはここで検出される）
COPY . /tmp/kong-plugin-obo
RUN cd /tmp/kong-plugin-obo \
    && luarocks make \
    && rm -rf /tmp/kong-plugin-obo

# Kong 公式イメージの実行ユーザーに戻す
USER kong

# obo プラグイン入り Kong Gateway データプレーンイメージ
# compose.yaml（Konnect DP 構成）の kong サービスがこの Dockerfile をビルドして使う
# ベースは既存 DP 構成に合わせて Kong Gateway (Enterprise) 3.14 系
FROM kong/kong-gateway:3.14.0.7

# luarocks make はイメージ内の LuaRocks ツリーへ書き込むため root で実行する
USER root

# リポジトリ一式をコピーして rockspec 経由でインストールする
# （rockspec の build.modules が唯一のインストール定義。記載漏れはここで検出される。
#   .env や cluster-certs/ は .dockerignore で除外済み — レイヤーに焼き込まないこと）
COPY . /tmp/kong-plugin-obo
RUN cd /tmp/kong-plugin-obo \
    && luarocks make \
    && rm -rf /tmp/kong-plugin-obo

# Kong 公式イメージの実行ユーザーに戻す
USER kong

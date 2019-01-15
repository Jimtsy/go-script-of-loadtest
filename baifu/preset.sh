#!/bin/bash

# mock接口状态设置

mockerURL="http://"


curl ${mockerURL}/mockerURL/state/UPayV2PayResultCode/PAY_SUCCESS/set/4
echo "\n"

curl ${mockerURL}/mockerURL/state/UPayV2PayResultCode/PAY_IN_PROGRESS/set/1
echo "\n"

curl ${mockerURL}/mockerURL/state/UPayV2PayResultCode/PAY_FAIL_ERROR/set/0
echo "\n"

curl ${mockerURL}/mockerURL/state/UPayV2QueryResultCode/SUCCESS/set/4
echo "\n"

curl ${mockerURL}/mockerURL/state/UPayV2QueryResultCode/IN_PROG/set/1
echo "\n"

curl ${mockerURL}/mockerURL/state/UPayV2QueryResultCode/FAIL/set/0
echo "\n"

# 设置/upay-gateway/upay/v2/pay 延迟/抖动
curl ${mockerURL}/mockerURL/latency/upay-gateway_upay_v2_pay/set/0/0
echo "\n"

# 设置/upay-gateway/upay/v2/query 延迟/抖动
curl ${mockerURL}/mockerURL/latency/upay-gateway_upay_v2_query/set/0/0
echo "\n"

#!/bin/bash
# Bambu Lab API - curl commands
# Set your token: export BAMBU_TOKEN="your_jwt_here"

TOKEN="${BAMBU_TOKEN}"
BASE="https://api.bambulab.com/v1"

# [aftersale-service] POST /aftersale-service/makerworld/totalunreadcount
curl -s -X POST "$BASE/aftersale-service/makerworld/totalunreadcount" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [aftersale-service] POST /aftersale-service/trouble/totalunreadcount
curl -s -X POST "$BASE/aftersale-service/trouble/totalunreadcount" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [analysis-st] GET /analysis-st/tag/
curl -s -X GET "$BASE/analysis-st/tag/?UID=65c31ea0-cd74-11ed-b18f-39cf197fa3d4" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [app2] POST /app2/home
curl -s -X POST "$BASE/app2/home" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [app2] POST /app2/makerworld
curl -s -X POST "$BASE/app2/makerworld" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] GET /comment-service/comment/{id}/detail
curl -s -X GET "$BASE/comment-service/comment/{id}/detail" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] POST /comment-service/comment/{id}/like
curl -s -X POST "$BASE/comment-service/comment/{id}/like" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] GET /comment-service/comment/{id}/reply
curl -s -X GET "$BASE/comment-service/comment/{id}/reply" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] GET /comment-service/commentandrating
curl -s -X GET "$BASE/comment-service/commentandrating?designId=2358777&offset=0&limit=20&type=0&sort=0" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] GET /comment-service/messagesession/list
curl -s -X GET "$BASE/comment-service/messagesession/list?userSelect=all&typeSelect=all&projectScope=0&offset=0&limit=2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [comment-service] GET /comment-service/rating/inst/{id}
curl -s -X GET "$BASE/comment-service/rating/inst/{id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-recommend-service] GET /design-recommend-service/my/for-you
curl -s -X GET "$BASE/design-recommend-service/my/for-you?limit=20&offset=0&seed=0&acceptTypes=0,2,5,6,3" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/design/{id}
curl -s -X GET "$BASE/design-service/design/{id}?trafficSource=recommend&visitHistory=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/design/{id}/remixed
curl -s -X GET "$BASE/design-service/design/{id}/remixed" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/draft/sliceerror
curl -s -X GET "$BASE/design-service/draft/sliceerror" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/favorites/designs/{id}
curl -s -X GET "$BASE/design-service/favorites/designs/{id}?offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/instance/{id}/f3mf
curl -s -X GET "$BASE/design-service/instance/{id}/f3mf?type=preview" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] GET /design-service/my/design/favoriteslist
curl -s -X GET "$BASE/design-service/my/design/favoriteslist?designId=2358777" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-service] POST /design-service/my/design/like
curl -s -X POST "$BASE/design-service/my/design/like?offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-user-service] GET /design-user-service/my/preference
curl -s -X GET "$BASE/design-user-service/my/preference" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [design-user-service] GET /design-user-service/my/profile
curl -s -X GET "$BASE/design-user-service/my/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/slicer/resource
curl -s -X GET "$BASE/iot-service/api/slicer/resource?slicer/info/bbl=01.00.00.04" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/slicer/setting
curl -s -X GET "$BASE/iot-service/api/slicer/setting?version=1.0.0.1&public=false" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/user/applications/{token}/cert
curl -s -X GET "$BASE/iot-service/api/user/applications/{token}/cert?aes256=ViXLbxLlpySiAu213oN2EjKWdOiocbew55eZNF9x06wkcWoI5pXE9fmQS1nqPnVJQRNoMK0k3XorwZ0CKTcA_5MFRr-U-Dwkkm7RFcwFjGiQCeb_wNkEqttQ4FiZH5ucKdHdk9vBhvBGU3rVInkUDZNxsjFV2joqTr9GkudF2jBDIavg7Vr4SPH0-w6C_o9G8muPzfV36h5PkiX1HMhcsivrBux3CbSbpG6ktnAu3dZoWWRo3Hunw3xTC4YKzo3Axwa3A5WRSfhsofZdPMSQaQOb49sGma07uK7Hd2BYDl2LNHC3KCF0PxMnxAZrdcfYFMmBwwNkrX8GdopH95wTcw==" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/user/bind
curl -s -X GET "$BASE/iot-service/api/user/bind" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/user/profile/{id}
curl -s -X GET "$BASE/iot-service/api/user/profile/{id}?model_id=USf86740b8413939" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] GET /iot-service/api/user/task/{id}
curl -s -X GET "$BASE/iot-service/api/user/task/{id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [iot-service] POST /iot-service/api/user/ttcode
curl -s -X POST "$BASE/iot-service/api/user/ttcode" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [operation-service] GET /operation-service/apphomepage
curl -s -X GET "$BASE/operation-service/apphomepage" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [operation-service] GET /operation-service/configuration
curl -s -X GET "$BASE/operation-service/configuration" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [point-service] GET /point-service/boost/boostdesign
curl -s -X GET "$BASE/point-service/boost/boostdesign?designId=2358777" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [report-service] GET /report-service/report/classification
curl -s -X GET "$BASE/report-service/report/classification?source=message" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [search-service] GET /search-service/design/{id}/relate
curl -s -X GET "$BASE/search-service/design/{id}/relate?offset=0&limit=20&scene=1" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [search-service] GET /search-service/homepage/nav
curl -s -X GET "$BASE/search-service/homepage/nav" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [search-service] POST /search-service/recommand/youlike
curl -s -X POST "$BASE/search-service/recommand/youlike" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [search-service] GET /search-service/select/design/nav
curl -s -X GET "$BASE/search-service/select/design/nav?navKey=Trending&offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [task-service] GET /task-service/user/taskv2/multi
curl -s -X GET "$BASE/task-service/user/taskv2/multi?taskNames=app_newbie_task_v2,app_newbie_task_v3" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/latest/app
curl -s -X GET "$BASE/user-service/latest/app" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/message/count
curl -s -X GET "$BASE/user-service/my/message/count" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] POST /user-service/my/message/device/tasks/read
curl -s -X POST "$BASE/user-service/my/message/device/tasks/read" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/message/device/taskstatus
curl -s -X GET "$BASE/user-service/my/message/device/taskstatus" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/message/latest
curl -s -X GET "$BASE/user-service/my/message/latest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] POST /user-service/my/message/read
curl -s -X POST "$BASE/user-service/my/message/read" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/messages
curl -s -X GET "$BASE/user-service/my/messages?type=1&offset=0&limit=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/model/profile
curl -s -X GET "$BASE/user-service/my/model/profile?profileId=635995371&modelId=US932767835d32ea" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/task/printedplates
curl -s -X GET "$BASE/user-service/my/task/printedplates?instanceId=2626238" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] GET /user-service/my/task/{id}
curl -s -X GET "$BASE/user-service/my/task/{id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# [user-service] POST /user-service/user/devicetoken
curl -s -X POST "$BASE/user-service/user/devicetoken" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

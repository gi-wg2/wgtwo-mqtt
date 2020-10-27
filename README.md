# WGTwo MQTT

```shell script
protoc \
  --go_out=intern \
  --go_opt=paths=source_relative \
  --go-grpc_out=intern \
  --go-grpc_opt=paths=source_relative \
  proto/*.proto
```
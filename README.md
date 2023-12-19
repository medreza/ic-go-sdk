# ic-go-sdk


This is AccelByte's IC Go SDK for integrating with IC in Go projects.

## Usage

### Importing package

```go
import "github.com/AccelByte/ic-go-sdk"
```

### Creating default IC client

```go
cfg := &iam.Config{
    BaseURL: "<IAM URL>",
    ClientID: "<client ID>",
    ClientSecret: "<client secret>",
}

client := iam.NewDefaultClient(cfg)

cfg := &ic.Config{
    BaseURL:      "<IAM URL>",
    ClientID:     "<client ID>",
    ClientSecret: "<client secret>",
}
client := ic.NewDefaultClient(cfg)
```

### Validate config

```go
_, err := client.ClientToken()
if err != nil {
	logrus.Fatalf("ic-go-sdk start err: %v \n", err)
}
```

### Example:
1. replace the placeholder in ```example/example.go```
2. ```go build example.go```
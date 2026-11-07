// Narrow UAC helper. It cannot accept executable paths, arbitrary service
// methods, or a user identity selected by an unprivileged frontend.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
	"vault443/internal/ipc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	method := ""
	var params []any
	if len(os.Args) == 2 && os.Args[1] == "--grant-console" {
		method = "GrantConsoleOperator"
	} else if len(os.Args) == 3 && os.Args[1] == "--request" {
		data, err := base64.RawURLEncoding.DecodeString(os.Args[2])
		if err != nil || len(data) > 64<<10 {
			return errors.New("invalid administrative request")
		}
		var request struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if json.Unmarshal(data, &request) != nil {
			return errors.New("invalid administrative request")
		}
		method, params = request.Method, request.Params
		switch method {
		case "SetBootProfile", "SetVPNBinding":
			if len(params) != 1 {
				return errors.New("invalid administrative parameters")
			}
			if _, ok := params[0].(string); !ok {
				return errors.New("invalid administrative parameters")
			}
		default:
			return errors.New("unsupported administrative action")
		}
	} else {
		return errors.New("use --grant-console or a frontend administrative request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := ipc.PipeCall(ctx, method, params...)
	return err
}

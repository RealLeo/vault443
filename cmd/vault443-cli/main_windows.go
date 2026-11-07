// Local diagnostic/acceptance client. Import parameters are read from stdin,
// never from command-line arguments visible to other desktop processes.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
	"vault443/internal/ipc"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: vault443-cli METHOD < parameters.json")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		os.Exit(2)
	}
	var params []any
	if len(data) > 0 && json.Unmarshal(data, &params) != nil {
		fmt.Fprintln(os.Stderr, "parameters must be a JSON array")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := ipc.PipeCall(ctx, os.Args[1], params...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(result))
}

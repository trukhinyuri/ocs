// A small independent host for the sealed demonstration contract.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

const frameLimit = 1048576
const statusPin = "5eba19b3801e90c2d161fdd49c46152a5c8b8aae82c238b8557dbc6948a1e19a"

var errObject = errors.New("expected an object")

type object = map[string]any
type exchange func([]byte) ([]byte, error)

var errorKinds = map[string]string{
	"-32700": "parse", "-32600": "request", "-32601": "method", "-32602": "params", "-32603": "internal",
	"-33001": "denied", "-33004": "cancelled", "-33005": "deadline", "-33008": "incompatible",
	"-33009": "input", "-33014": "pin", "-32001": "output", "-32002": "conflict", "-32003": "busy",
	"-32004": "unavailable", "-32005": "unknown_effect",
}

func tree(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '{' {
			result := object{}
			for d.More() {
				tok, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := tok.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				if _, exists := result[key]; exists {
					return nil, errors.New("duplicate JSON key")
				}
				result[key], err = tree(d, depth+1)
				if err != nil {
					return nil, err
				}
			}
			_, err = d.Token()
			return result, err
		}
		if t == '[' {
			result := []any{}
			for d.More() {
				item, e := tree(d, depth+1)
				if e != nil {
					return nil, e
				}
				result = append(result, item)
			}
			_, err = d.Token()
			return result, err
		}
		return nil, errors.New("invalid delimiter")
	case json.Number:
		f, e := t.Float64()
		if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.New("invalid number")
		}
		if math.Trunc(f) == f && math.Abs(f) > 9007199254740991 {
			return nil, errors.New("nonportable integer")
		}
		return t, nil
	default:
		return t, nil
	}
}

// The standard decoder replaces unpaired surrogate escapes. Reject them before decoding.
func validEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		v, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(data) || string(data[i+1:i+3]) != "\\u" {
				return false
			}
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inString
}

func decode(data []byte) (object, error) {
	if len(data) > frameLimit || !utf8.Valid(data) || !validEscapes(data) {
		return nil, errors.New("invalid wire data")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, e := tree(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	o, ok := v.(object)
	if !ok {
		return nil, errObject
	}
	return o, nil
}

func invoke(send exchange, id, method string, params object, max int) (object, error) {
	msg, e := json.Marshal(object{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if e != nil {
		return nil, e
	}
	if len(msg) > max {
		return nil, errors.New("request exceeds negotiated limit")
	}
	raw, e := send(msg)
	if e != nil {
		return nil, e
	}
	if len(raw) > max {
		return nil, errors.New("response exceeds negotiated limit")
	}
	o, e := decode(raw)
	if e != nil {
		return nil, e
	}
	if len(o) != 3 || o["jsonrpc"] != "2.0" || o["id"] != id {
		return nil, errors.New("mismatched response")
	}
	if failure, ok := o["error"].(object); ok {
		code, ok := failure["code"].(json.Number)
		data, hasData := failure["data"].(object)
		message, hasMessage := failure["message"].(string)
		if !ok || !hasData || !hasMessage || message == "" || len(failure) != 3 {
			return nil, errors.New("invalid error response")
		}
		kind, validKind := data["kind"].(string)
		if !validKind || errorKinds[code.String()] != kind || kind == "" {
			return nil, errors.New("invalid error classification")
		}
		return nil, fmt.Errorf("executor refused with %s (%s)", kind, code.String())
	}
	result, ok := o["result"].(object)
	if !ok {
		return nil, errors.New("invalid result")
	}
	return result, nil
}

func stdio(ctx context.Context, entry string) (exchange, func(), error) {
	cmd := exec.CommandContext(ctx, "python3", "-I", entry)
	cmd.Dir = filepath.Dir(entry)
	cmd.Env = []string{}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return nil, nil, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return nil, nil, e
	}
	if e = cmd.Start(); e != nil {
		return nil, nil, e
	}
	reader := bufio.NewReaderSize(stdout, frameLimit+1)
	send := func(msg []byte) ([]byte, error) {
		if _, e := stdin.Write(append(msg, '\n')); e != nil {
			if deadline := ctx.Err(); deadline != nil {
				return nil, deadline
			}
			return nil, e
		}
		raw, e := reader.ReadSlice('\n')
		if deadline := ctx.Err(); deadline != nil {
			return nil, deadline
		}
		if e != nil {
			return nil, e
		}
		return raw[:len(raw)-1], nil
	}
	return send, func() { stdin.Close(); cmd.Wait() }, nil
}

func network(ctx context.Context, endpoint, token string) (exchange, func(), error) {
	u, e := url.Parse(endpoint)
	if e != nil {
		return nil, nil, e
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Scheme != "http" || u.User != nil || u.Path != "/ocs" || u.RawQuery != "" || u.Fragment != "" || token == "" {
		return nil, nil, errors.New("the example network grant requires a numeric loopback endpoint and a test credential")
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(msg []byte) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(msg))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("peer returned HTTP %d", res.StatusCode)
		}
		media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			return nil, errors.New("unexpected peer response media type")
		}
		return io.ReadAll(io.LimitReader(res.Body, frameLimit+1))
	}
	return send, transport.CloseIdleConnections, nil
}

func status(manifest, resource, peer string) (result object, finalErr error) {
	if resource != "demo" {
		return nil, errors.New("denied: resource outside fixture grant")
	}
	path, e := filepath.Abs(manifest)
	if e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != statusPin {
		return nil, errors.New("unsupported descriptor pin")
	}
	until := time.Now().Add(5 * time.Second)
	wallDeadline := until.UTC()
	deadline := wallDeadline.Format("2006-01-02T15:04:05.000Z")
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	var send exchange
	var closeFn func()
	if peer == "" {
		entry := filepath.Join(filepath.Dir(path), "executor.py")
		info, e := os.Lstat(entry)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("invalid entry")
		}
		send, closeFn, e = stdio(ctx, entry)
		if e != nil {
			return nil, e
		}
	} else {
		send, closeFn, e = network(ctx, peer, os.Getenv("OCS_DEMO_TOKEN"))
		if e != nil {
			return nil, e
		}
	}
	defer func() {
		closeFn()
		now := time.Now()
		if finalErr == nil && (!now.Before(until) || !now.UTC().Before(wallDeadline)) {
			result, finalErr = nil, context.DeadlineExceeded
		}
	}()
	desc, e := invoke(send, "1", "ocs.describe", object{"protocols": []string{"0.1"}, "requiredFeatures": []string{}, "meta": object{"deadline": deadline}}, frameLimit)
	if e != nil {
		return nil, e
	}
	if len(desc) != 6 || desc["protocol"] != "0.1" || desc["packageId"] != "org.example.status" || desc["packageVersion"] != "0.1.0" || desc["manifestDigest"] != statusPin {
		return nil, errors.New("incompatible negotiated descriptor")
	}
	advertised, ok := desc["features"].([]any)
	if !ok || len(advertised) != 0 {
		return nil, errors.New("unexpected fixture features")
	}
	number, ok := desc["maxFrameBytes"].(json.Number)
	if !ok {
		return nil, errors.New("invalid frame limit")
	}
	limit, e := number.Int64()
	if e != nil || limit < 1 || limit > frameLimit {
		return nil, errors.New("invalid frame limit")
	}
	res, e := invoke(send, "2", "tool.call", object{"operation": "example.status.read", "version": "1.0.0", "input": object{"resourceId": resource}, "meta": object{"deadline": deadline, "protocol": "0.1", "manifestDigest": statusPin}}, int(limit))
	if e != nil {
		return nil, e
	}
	data, ok := res["data"].(object)
	if len(res) != 1 || !ok || len(data) != 2 || data["resourceId"] != resource || (data["state"] != "ready" && data["state"] != "degraded") {
		return nil, errors.New("invalid output")
	}
	if !time.Now().Before(until) {
		return nil, errors.New("deadline elapsed before delivering response")
	}
	return data, nil
}

func main() {
	manifest := flag.String("manifest", "examples/status/ocs.json", "reviewed demonstration package")
	resource := flag.String("resource", "demo", "authorized fixture resource")
	peer := flag.String("loopback-peer", "", "isolated development peer endpoint")
	executor := flag.Bool("serve", false, "run the independent stdio executor with its reviewed manifest")
	flag.Parse()
	if *executor {
		if err := serve(*manifest, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	data, e := status(*manifest, *resource, *peer)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(data); e != nil {
		os.Exit(1)
	}
}

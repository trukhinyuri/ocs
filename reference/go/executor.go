package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const executorPin = "5ea8c364b740756a88010748b0cc888b2746fbf2d00fbdba3df2d52d9c677390"

var featureName = regexp.MustCompile("^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+/[0-9]+\\.[0-9]+$")
var operationName = regexp.MustCompile("^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$")
var hexDigest = regexp.MustCompile("^[0-9a-f]{64}$")
var semanticVersion = regexp.MustCompile("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*))?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$")

func versionOK(v string) bool {
	parts := semanticVersion.FindStringSubmatch(v)
	if len(v) > 128 || parts == nil {
		return false
	}
	for _, part := range strings.Split(parts[5], ".") {
		if len(part) > 1 && part[0] == '0' && strings.Trim(part, "0123456789") == "" {
			return false
		}
	}
	return true
}

func nonempty(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func keys(o object, required []string, optional ...string) bool {
	if o == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return false
		}
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range o {
		if !allowed[k] {
			return false
		}
	}
	return true
}

func stringSet(v any, pattern *regexp.Regexp) (map[string]bool, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, member := range list {
		s, ok := member.(string)
		if !ok || s == "" || seen[s] || (pattern != nil && !pattern.MatchString(s)) {
			return nil, false
		}
		seen[s] = true
	}
	return seen, true
}

func fault(code int, kind, message string) object {
	return object{"error": object{"code": code, "message": message, "data": object{"kind": kind}}}
}

func deadline(meta object) object {
	s, _ := meta["deadline"].(string)
	until, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil || len(s) != 24 || s[19] != '.' {
		return fault(-32602, "params", "Malformed UTC deadline.")
	}
	if !time.Now().Before(until) {
		return fault(-33005, "deadline", "Deadline elapsed.")
	}
	return nil
}

type session struct{ ready bool }

func (s *session) dispatch(method string, p object) object {
	meta, _ := p["meta"].(object)
	switch method {
	case "ocs.describe":
		s.ready = false
		if !keys(p, []string{"protocols", "requiredFeatures", "meta"}) || !keys(meta, []string{"deadline"}, "traceId") {
			return fault(-32602, "params", "Malformed negotiation.")
		}
		if v, ok := meta["traceId"]; ok && !nonempty(v) {
			return fault(-32602, "params", "Invalid trace ID.")
		}
		if f := deadline(meta); f != nil {
			return f
		}
		protocols, valid := stringSet(p["protocols"], nil)
		features, validFeatures := stringSet(p["requiredFeatures"], featureName)
		if !valid || len(protocols) == 0 || !validFeatures {
			return fault(-32602, "params", "Invalid negotiation lists.")
		}
		if !protocols["0.1"] || len(features) > 0 {
			return fault(-33008, "incompatible", "Unsupported protocol or feature.")
		}
		s.ready = true
		return object{"result": object{"protocol": "0.1", "packageId": "org.example.status-go", "packageVersion": "0.1.0", "manifestDigest": executorPin, "features": []string{}, "maxFrameBytes": frameLimit}}
	case "tool.call":
		if !keys(p, []string{"operation", "version", "input", "meta"}) || !keys(meta, []string{"protocol", "manifestDigest", "deadline"}, "traceId", "parentCallId", "idempotencyKey") {
			return fault(-32602, "params", "Malformed invocation.")
		}
		if f := deadline(meta); f != nil {
			return f
		}
		for _, k := range []string{"traceId", "parentCallId", "idempotencyKey"} {
			if v, ok := meta[k]; ok && !nonempty(v) {
				return fault(-32602, "params", "Invalid call metadata.")
			}
		}
		pin, _ := meta["manifestDigest"].(string)
		op, _ := p["operation"].(string)
		version, _ := p["version"].(string)
		if !hexDigest.MatchString(pin) || !operationName.MatchString(op) || len(op) > 160 || !versionOK(version) {
			return fault(-32602, "params", "Malformed operation identity or descriptor digest.")
		}
		if !s.ready || meta["protocol"] != "0.1" {
			return fault(-33008, "incompatible", "Negotiate a compatible binding.")
		}
		if pin != executorPin {
			return fault(-33014, "pin", "Changed descriptor.")
		}
		if op != "example.status.read" {
			return fault(-32601, "method", "Unexported operation.")
		}
		if version != "1.0.0" {
			return fault(-33008, "incompatible", "Unsupported contract version.")
		}
		in, _ := p["input"].(object)
		id, ok := in["resourceId"].(string)
		if !keys(in, []string{"resourceId"}) || !ok || utf8.RuneCountInString(id) > 80 || id == "" {
			return object{"error": object{"code": -33009, "message": "Invalid resource identifier.", "data": object{"kind": "input", "path": "/resourceId"}}}
		}
		if id != "demo" {
			return fault(-33001, "denied", "Unbound resource.")
		}
		return object{"result": object{"data": object{"resourceId": id, "state": "ready"}}}
	default:
		return fault(-32601, "method", "Unknown method.")
	}
}

func (s *session) respond(raw []byte) object {
	msg, err := decode(raw)
	var id any
	var reply object
	if err != nil {
		if errors.Is(err, errObject) {
			reply = fault(-32600, "request", "Expected one object.")
		} else {
			reply = fault(-32700, "parse", "Invalid JSON.")
		}
	} else {
		method, ok := msg["method"].(string)
		params, valid := msg["params"].(object)
		requestID, hasValidID := msg["id"].(string)
		if hasValidID && requestID != "" && utf8.RuneCountInString(requestID) <= 128 {
			id = requestID
		}
		validEnvelope := ok && method != "" && valid && msg["jsonrpc"] == "2.0"
		if validEnvelope && keys(msg, []string{"method", "params", "jsonrpc"}) {
			return nil
		}
		if !validEnvelope || id == nil || !keys(msg, []string{"method", "params", "jsonrpc", "id"}) {
			reply = fault(-32600, "request", "Invalid envelope.")
		} else {
			reply = s.dispatch(method, params)
		}
	}
	reply["jsonrpc"] = "2.0"
	reply["id"] = id
	return reply
}

func serve(manifest string, input io.Reader, output io.Writer) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != executorPin {
		return errors.New("unreviewed executor descriptor")
	}
	reader := bufio.NewReaderSize(input, frameLimit+1)
	encoder := json.NewEncoder(output)
	s := session{}
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		if reply := s.respond(line[:len(line)-1]); reply != nil {
			if err := encoder.Encode(reply); err != nil {
				return err
			}
		}
	}
}

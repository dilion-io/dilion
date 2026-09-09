// A test-only, in-memory peer for cross-language interoperability. Never mount
// this as an auth service: there is intentionally no account/session system.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bytemare/opaque"
)

const userID = "interop-user"
const serverID = "dilion:interop"

func main() {
	conf := opaque.DefaultConfiguration()
	server, err := conf.Server()
	if err != nil {
		panic(err)
	}
	sk, pk := conf.KeyGen()
	if err := server.SetKeyMaterial(&opaque.ServerKeyMaterial{
		Identity: []byte(serverID), PrivateKey: sk, PublicKeyBytes: pk.Encode(), OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}); err != nil {
		panic(err)
	}
	var record *opaque.ClientRecord
	var state *opaque.ServerOutput
	enc := json.NewEncoder(os.Stdout)
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024), 65536)
	for in.Scan() {
		var request struct{ Operation, Message string }
		reply := map[string]any{}
		err := json.Unmarshal(in.Bytes(), &request)
		var data []byte
		if err == nil {
			data, err = base64.RawURLEncoding.DecodeString(request.Message)
		}
		if err == nil {
			switch request.Operation {
			case "register-start":
				msg, e := server.Deserialize.RegistrationRequest(data)
				err = e
				if err == nil {
					response, e := server.RegistrationResponse(msg, []byte(userID), nil)
					err = e
					if err == nil {
						reply["message"] = base64.RawURLEncoding.EncodeToString(response.Serialize())
					}
				}
			case "register-finish":
				msg, e := server.Deserialize.RegistrationRecord(data)
				err = e
				if err == nil {
					record = &opaque.ClientRecord{RegistrationRecord: msg, ClientIdentity: []byte(userID), CredentialIdentifier: []byte(userID)}
				}
			case "login-start":
				msg, e := server.Deserialize.KE1(data)
				err = e
				if err == nil {
					response, output, e := server.GenerateKE2(msg, record)
					err = e
					if err == nil {
						state = output
						reply["message"] = base64.RawURLEncoding.EncodeToString(response.Serialize())
					}
				}
			case "login-finish":
				msg, e := server.Deserialize.KE3(data)
				err = e
				if state == nil {
					err = fmt.Errorf("missing or consumed login state")
				}
				if err == nil {
					err = server.LoginFinish(msg, state.ClientMAC)
					if err == nil {
						// Synthetic test secret only, for byte-for-byte assertions.
						reply["session_key"] = base64.RawURLEncoding.EncodeToString(state.SessionSecret)
					}
				}
				if state != nil {
					clear(state.SessionSecret)
					clear(state.ClientMAC)
				}
				state = nil
			default:
				err = fmt.Errorf("unknown operation")
			}
		}
		if err != nil {
			reply["error"] = err.Error()
		}
		if err := enc.Encode(reply); err != nil {
			panic(err)
		}
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}

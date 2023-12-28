package rpc

import (
	"errors"
	"fmt"
	hadoop "github.com/colinmarc/hdfs/v2/internal/protocol/hadoop_common"
	"github.com/colinmarc/hdfs/v2/internal/sasl"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	krbtypes "github.com/jcmturner/gokrb5/v8/types"
	"net"
	"regexp"
	"sort"
)

const saslRpcCallId = -33

var (
	errKerberosNotSupported = errors.New("kerberos authentication not supported by namenode")
	krbSPNHost              = regexp.MustCompile(`\A[^/]+/(_HOST)([@/]|\z)`)
)

func (c *NamenodeConnection) doKerberosHandshake() error {
	// Start negotiation, and get the list of supported mechanisms in reply.
	err := c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_NEGOTIATE.Enum(),
	})
	if err != nil {
		return err
	}

	resp, err := c.readSaslResponse(hadoop.RpcSaslProto_NEGOTIATE)
	if err != nil {
		return err
	}

	var krbAuth, tokenAuth *hadoop.RpcSaslProto_SaslAuth
	for _, m := range resp.GetAuths() {
		switch *m.Method {
		case "KERBEROS":
			krbAuth = m
		case "TOKEN":
			tokenAuth = m
		default:
		}
	}

	if krbAuth == nil {
		return errKerberosNotSupported
	}

	// Get a ticket from Kerberos, and send the initial token to the namenode.
	token, sessionKey, err := c.getKerberosTicket()
	if err != nil {
		return err
	}

	if tokenAuth != nil {
		challenge, err := sasl.ParseChallenge(tokenAuth.Challenge)
		if err != nil {
			return err
		}

		// Some versions of HDP 3.x expect us to pick the highest Qop, and
		// return a malformed response otherwise.
		sort.Sort(challenge.Qop)
		qop := challenge.Qop[0]

		switch qop {
		case sasl.QopPrivacy, sasl.QopIntegrity:
			// Switch to SASL RPC handler
			c.transport = &saslTransport{
				basicTransport: basicTransport{
					clientID: c.ClientID,
				},
				sessionKey: sessionKey,
				privacy:    qop == sasl.QopPrivacy,
			}
		case sasl.QopAuthentication:
			// No special transport is required.
		default:
			return errors.New("unexpected QOP in challenge")
		}
	}

	err = c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_INITIATE.Enum(),
		Token: token.MechTokenBytes,
		Auths: []*hadoop.RpcSaslProto_SaslAuth{krbAuth},
	})
	if err != nil {
		return err
	}

	// In response, we get a server token to verify.
	resp, err = c.readSaslResponse(hadoop.RpcSaslProto_CHALLENGE)
	if err != nil {
		return err
	}

	tokenFromResp := resp.GetToken()

	var signedBytes []byte

	// RFC 4121 Section.6
	// https://datatracker.ietf.org/doc/rfc4121/
	if tokenFromResp[0] == 0x60 {
		signedBytes, err = getInitiatorWrapTokenV1(tokenFromResp, sessionKey)
	} else {
		signedBytes, err = getInitiatorWrapTokenV2(tokenFromResp, sessionKey)
	}
	if err != nil {
		return err
	}

	err = c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_RESPONSE.Enum(),
		Token: signedBytes,
	})
	if err != nil {
		return err
	}

	// Read the final response. If it's a SUCCESS, then we're done here.
	_, err = c.readSaslResponse(hadoop.RpcSaslProto_SUCCESS)
	return err
}

func (c *NamenodeConnection) writeSaslRequest(req *hadoop.RpcSaslProto) error {
	rrh := newRPCRequestHeader(saslRpcCallId, c.ClientID)
	packet, err := makeRPCPacket(rrh, req)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(packet)
	return err
}

func (c *NamenodeConnection) readSaslResponse(expectedState hadoop.RpcSaslProto_SaslState) (*hadoop.RpcSaslProto, error) {
	rrh := &hadoop.RpcResponseHeaderProto{}
	resp := &hadoop.RpcSaslProto{}
	err := readRPCPacket(c.conn, rrh, resp)
	if err != nil {
		return nil, err
	} else if int32(rrh.GetCallId()) != saslRpcCallId {
		return nil, errors.New("unexpected sequence number")
	} else if rrh.GetStatus() != hadoop.RpcResponseHeaderProto_SUCCESS {
		return nil, &NamenodeError{
			method:    "sasl",
			message:   rrh.GetErrorMsg(),
			code:      int(rrh.GetErrorDetail()),
			exception: rrh.GetExceptionClassName(),
		}
	} else if resp.GetState() != expectedState {
		return nil, fmt.Errorf("unexpected SASL state: %s", resp.GetState().String())
	}

	return resp, nil
}

// getKerberosTicket returns an initial kerberos negotiation token and the
// paired session key, along with an error if any occured.
func (c *NamenodeConnection) getKerberosTicket() (spnego.NegTokenInit, krbtypes.EncryptionKey, error) {
	host, _, _ := net.SplitHostPort(c.host.address)
	spn := replaceSPNHostWildcard(c.kerberosServicePrincipleName, host)

	ticket, key, err := c.kerberosClient.GetServiceTicket(spn)
	if err != nil {
		return spnego.NegTokenInit{}, key, err
	}

	token, err := spnego.NewNegTokenInitKRB5(c.kerberosClient, ticket, key)
	return token, key, err
}

// replaceSPNHostWildcard substitutes the special string '_HOST' in the given
// SPN for the given (current) host.
func replaceSPNHostWildcard(spn, host string) string {
	res := krbSPNHost.FindStringSubmatchIndex(spn)
	if res == nil || res[2] == -1 {
		return spn
	}

	return spn[:res[2]] + host + spn[res[3]:]
}

func getInitiatorWrapTokenV1(initialToken []byte, sessionKey krbtypes.EncryptionKey) (signedToken []byte, err error) {
	var nnTokenV1 gssapi.WrapTokenV1
	err = nnTokenV1.Unmarshal(initialToken, true)
	if err != nil {
		return nil, err
	}
	_, err = nnTokenV1.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil {
		return nil, fmt.Errorf("invalid server token (v1): %s", err)
	}

	signed, err := gssapi.NewInitiatorWrapTokenV1(&nnTokenV1, sessionKey)
	if err != nil {
		return nil, err
	}

	signedBytes, err := signed.Marshal(sessionKey)
	if err != nil {
		return nil, err
	}

	return signedBytes, nil
}

func getInitiatorWrapTokenV2(initialToken []byte, sessionKey krbtypes.EncryptionKey) (signedToken []byte, err error) {
	var nnToken gssapi.WrapToken

	err = nnToken.Unmarshal(initialToken, true)
	if err != nil {
		return nil, err
	}
	_, err = nnToken.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("invalid server token: %s", err)
	}
	// Sign the payload and send it back to the namenode.
	// TODO: Make sure we can support what is required based on what's in the
	// payload.
	signed, err := gssapi.NewInitiatorWrapToken(nnToken.Payload, sessionKey)
	if err != nil {
		return nil, err
	}

	signedBytes, err := signed.Marshal()
	if err != nil {
		return nil, err
	}

	return signedBytes, nil
}

package rpc

import (
	"bytes"
	"fmt"
	hadoop "github.com/colinmarc/hdfs/v2/internal/protocol/hadoop_common"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	krbtypes "github.com/jcmturner/gokrb5/v8/types"
	"google.golang.org/protobuf/proto"
	"io"
)

// saslTransport implements encrypted or signed RPC.
type saslTransport struct {
	basicTransport

	// sessionKey is the encryption key used to decrypt and encrypt the payload.
	sessionKey krbtypes.EncryptionKey
	// privacy indicates full message encryption
	privacy bool
}

// readResponse reads a SASL-wrapped RPC response.
func (t *saslTransport) readResponse(r io.Reader, method string, requestID int32, resp proto.Message) error {
	// First, read the sasl payload as a standard rpc response.
	sasl := hadoop.RpcSaslProto{}
	err := t.basicTransport.readResponse(r, method, saslRpcCallId, &sasl)
	if err != nil {
		return err
	} else if sasl.GetState() != hadoop.RpcSaslProto_WRAP {
		return fmt.Errorf("unexpected SASL state: %s", sasl.GetState().String())
	}

	// The SaslProto contains the actual payload.
	saslToken := sasl.GetToken()

	rrh := &hadoop.RpcResponseHeaderProto{}

	// RFC 4121 Section.6
	// https://datatracker.ietf.org/doc/rfc4121/
	if saslToken[0] == 0x60 {
		err = t.decryptResponseWithWarpTokenV1(saslToken, resp, rrh)
	} else {
		err = t.decryptResponseWithWarpTokenV2(saslToken, resp, rrh)
	}
	if err != nil {
		return err
	}

	if int32(rrh.GetCallId()) != requestID {
		return errUnexpectedSequenceNumber
	} else if rrh.GetStatus() != hadoop.RpcResponseHeaderProto_SUCCESS {
		return &NamenodeError{
			method:    method,
			message:   rrh.GetErrorMsg(),
			code:      int(rrh.GetErrorDetail()),
			exception: rrh.GetExceptionClassName(),
		}
	}

	return nil
}

func (t *saslTransport) decryptResponseWithWarpTokenV1(saslToken []byte, resp proto.Message, rrh *hadoop.RpcResponseHeaderProto) (err error) {
	var wrapTokenV1 gssapi.WrapTokenV1
	err = wrapTokenV1.Unmarshal(saslToken, true)
	if err != nil {
		return err
	}
	if t.privacy {
		// Decrypt the blob, which then looks like a normal RPC response.
		decrypted, err := crypto.DecryptMessage(wrapTokenV1.Payload, t.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return err
		}

		err = readRPCPacket(bytes.NewReader(decrypted), rrh, resp)
		if err != nil {
			return err
		}
	} else {
		// Verify the checksum; the blob is just a normal RPC response.
		_, err = wrapTokenV1.Verify(t.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return fmt.Errorf("unverifiable message from namenode: %s", err)
		}

		err = readRPCPacket(bytes.NewReader(wrapTokenV1.Payload), rrh, resp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *saslTransport) decryptResponseWithWarpTokenV2(saslToken []byte, resp proto.Message, rrh *hadoop.RpcResponseHeaderProto) (err error) {
	var wrapToken gssapi.WrapToken
	err = wrapToken.Unmarshal(saslToken, true)
	if err != nil {
		return err
	}
	if t.privacy {
		// Decrypt the blob, which then looks like a normal RPC response.
		decrypted, err := crypto.DecryptMessage(wrapToken.Payload, t.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return err
		}

		err = readRPCPacket(bytes.NewReader(decrypted), rrh, resp)
		if err != nil {
			return err
		}
	} else {
		// Verify the checksum; the blob is just a normal RPC response.
		_, err = wrapToken.Verify(t.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return fmt.Errorf("unverifiable message from namenode: %s", err)
		}

		err = readRPCPacket(bytes.NewReader(wrapToken.Payload), rrh, resp)
		if err != nil {
			return err
		}
	}
	return nil
}

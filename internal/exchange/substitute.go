package exchange

import (
	"encoding/json"

	"github.com/keycardai/go-sdk/oauth"
)

// substituteUserHeader is the JOSE header for the unsigned substitute-user
// token. The type is the vendor media type that the zone reads.
const substituteUserHeader = `{"typ":"vnd.kc.su+jwt","alg":"none"}`

// substituteUserToken builds the unsigned JWT that names the user an
// exchange impersonates, sent as the subject token of type
// oauth.SubstituteUserTokenType. The trailing dot marks the absent signature
// segment. The zone's policy, not a signature, decides whether the
// authenticated client may act for the user.
func substituteUserToken(user string) string {
	payload, _ := json.Marshal(struct { //nolint:errchkjson // a struct of one string always encodes
		Sub string `json:"sub"`
	}{Sub: user})
	return oauth.Base64URLEncode([]byte(substituteUserHeader)) + "." + oauth.Base64URLEncode(payload) + "."
}

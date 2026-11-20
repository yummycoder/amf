package context

import (
	"encoding/binary"
	"sync"

	"github.com/free5gc/aper"
	"github.com/nycu-ucr/nas/nasMessage"
	"github.com/nycu-ucr/ngap/ngapType"
	"github.com/nycu-ucr/openapi/models"
)

type SmContext struct {
	mu sync.RWMutex // protect the following fields

	// pdu session information
	pduSessionID int32
	smContextRef string
	snssai       models.Snssai
	dnn          string
	accessType   models.AccessType
	nsInstance   string
	userLocation models.UserLocation
	plmnID       models.PlmnId

	// SMF information
	smfID  string
	smfUri string
	hSmfID string
	vSmfID string

	// for duplicate pdu session id handling
	ulNASTransport *nasMessage.ULNASTransport
	duplicated     bool

	// NR-DC: UL TEID the SMF allocated for the split (secondary-node) leg of
	// this PDU session (LocalULTeidForSplitPDUSession). Learned from the
	// AdditionalULNGUUPTNLInformation IE of the PDUSessionResourceSetupRequestTransfer
	// the SMF hands us at establishment; 0 until seen.
	splitUlTeid uint32
}

func NewSmContext(pduSessionID int32) *SmContext {
	c := &SmContext{pduSessionID: pduSessionID}
	return c
}

func (c *SmContext) PduSessionID() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pduSessionID
}

func (c *SmContext) SetPduSessionID(id int32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pduSessionID = id
}

func (c *SmContext) SmContextRef() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.smContextRef
}

func (c *SmContext) SetSmContextRef(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.smContextRef = ref
}

func (c *SmContext) AccessType() models.AccessType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessType
}

func (c *SmContext) SetAccessType(accessType models.AccessType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessType = accessType
}

func (c *SmContext) Snssai() models.Snssai {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snssai
}

func (c *SmContext) SetSnssai(snssai models.Snssai) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snssai = snssai
}

func (c *SmContext) Dnn() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dnn
}

func (c *SmContext) SetDnn(dnn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dnn = dnn
}

func (c *SmContext) NsInstance() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nsInstance
}

func (c *SmContext) SetNsInstance(nsInstanceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nsInstance = nsInstanceID
}

func (c *SmContext) UserLocation() models.UserLocation {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userLocation
}

func (c *SmContext) SetUserLocation(userLocation models.UserLocation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.userLocation = userLocation
}

func (c *SmContext) PlmnID() models.PlmnId {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.plmnID
}

func (c *SmContext) SetPlmnID(plmnID models.PlmnId) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plmnID = plmnID
}

func (c *SmContext) SmfID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.smfID
}

func (c *SmContext) SetSmfID(smfID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.smfID = smfID
}

func (c *SmContext) SmfUri() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.smfUri
}

func (c *SmContext) SetSmfUri(smfUri string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.smfUri = smfUri
}

func (c *SmContext) HSmfID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hSmfID
}

func (c *SmContext) SetHSmfID(hsmfID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hSmfID = hsmfID
}

func (c *SmContext) VSmfID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.vSmfID
}

func (c *SmContext) SetVSmfID(vsmfID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vSmfID = vsmfID
}

func (c *SmContext) PduSessionIDDuplicated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.duplicated
}

func (c *SmContext) SetDuplicatedPduSessionID(duplicated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.duplicated = duplicated
}

func (c *SmContext) ULNASTransport() *nasMessage.ULNASTransport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ulNASTransport
}

func (c *SmContext) StoreULNASTransport(msg *nasMessage.ULNASTransport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ulNASTransport = msg
}

func (c *SmContext) DeleteULNASTransport() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ulNASTransport = nil
}

func (c *SmContext) SplitUlTeid() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.splitUlTeid
}

func (c *SmContext) SetSplitUlTeid(teid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.splitUlTeid = teid
}

// SplitUlTeidFromSetupRequestTransfer decodes a PDUSessionResourceSetupRequestTransfer
// and returns the GTP TEID carried in its first AdditionalULNGUUPTNLInformation item,
// i.e. the UPF-side UL TEID for the NR-DC split leg.
func SplitUlTeidFromSetupRequestTransfer(transfer []byte) (uint32, bool) {
	var t ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(transfer, &t, "valueExt"); err != nil {
		return 0, false
	}
	for _, ie := range t.ProtocolIEs.List {
		if ie.Id.Value != ngapType.ProtocolIEIDAdditionalULNGUUPTNLInformation ||
			ie.Value.AdditionalULNGUUPTNLInformation == nil {
			continue
		}
		for _, item := range ie.Value.AdditionalULNGUUPTNLInformation.List {
			gtp := item.NGUUPTNLInformation.GTPTunnel
			if gtp == nil || len(gtp.GTPTEID.Value) != 4 {
				continue
			}
			return binary.BigEndian.Uint32(gtp.GTPTEID.Value), true
		}
	}
	return 0, false
}

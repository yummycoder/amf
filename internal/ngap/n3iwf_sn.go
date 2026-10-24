package ngap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/free5gc/aper"
	amf_context "github.com/nycu-ucr/amf/internal/context"
	"github.com/nycu-ucr/amf/internal/logger"
	"github.com/nycu-ucr/amf/internal/sbi/consumer"
	"github.com/nycu-ucr/ngap/ngapConvert"
	"github.com/nycu-ucr/ngap/ngapType"
	"github.com/nycu-ucr/openapi/models"
)

type n3iwfSNAddReq struct {
	SUPI              string `json:"supi"`
	Kn3iwfHex         string `json:"kn3iwfHex"`
	PDUSessionID      uint32 `json:"pduSessionID"`
	QFIs              []int  `json:"qfis"`
	UplinkTEID        uint32 `json:"uplinkTEID"`
	UPFN3Address      string `json:"upfN3Address"`
	SecurityIntegrity bool   `json:"securityIntegrity"`
	SecurityCipher    bool   `json:"securityCipher"`
}

type n3iwfSNAddReply struct {
	Status       string `json:"status"`
	DownlinkTEID uint32 `json:"downlinkTEID"`
	N3IWFN3Addr  string `json:"n3iwfN3Addr"`
	UEInnerIP    string `json:"ueInnerIP"`
	Error        string `json:"error"`
}

func n3iwfSNEnabled() bool { return os.Getenv("N3IWF_SN_ENABLE") == "1" }

func n3iwfSNSocket() string {
	if v := os.Getenv("N3IWF_SN_SOCKET"); v != "" {
		return v
	}
	return "/run/l25gc/n3iwf-sn.sock"
}

func n3iwfSNUpf() string {
	if v := os.Getenv("N3IWF_SN_UPF"); v != "" {
		return v
	}
	return "192.168.4.2"
}

func n3iwfSNUlTeid() uint32 {
	if v := os.Getenv("N3IWF_SN_ULTEID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 1
}

// triggerN3iwfSNAdd derives the registration-anchored K_N3IWF_SN and delivers it
// plus the SN-leg params to the co-located N3IWF over the local unix socket. On a
// successful SN leg it pushes the N3IWF's DL tunnel to the SMF (A4) so the second
// DL FAR is installed for per-flow DL steering to the N3IWF.
func triggerN3iwfSNAdd(amfUe *amf_context.AmfUe, smContext *amf_context.SmContext, pduSessionID uint8, baseTransfer aper.OctetString) {
	k, err := amfUe.DerivateKN3IWFSN(pduSessionID)
	if err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: derive K_N3IWF_SN failed: %v", err)
		return
	}
	logger.NgapLog.Infof("N3IWF-SN: derived K_N3IWF_SN SUPI=%s PDU=%d key=%s",
		amfUe.Supi, pduSessionID, hex.EncodeToString(k))
	req := n3iwfSNAddReq{
		SUPI:              amfUe.Supi,
		Kn3iwfHex:         hex.EncodeToString(k),
		PDUSessionID:      uint32(pduSessionID),
		QFIs:              []int{1},
		UplinkTEID:        n3iwfSNUlTeid(),
		UPFN3Address:      n3iwfSNUpf(),
		SecurityIntegrity: true,
	}
	conn, err := net.DialTimeout("unix", n3iwfSNSocket(), 3*time.Second)
	if err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: dial %s: %v", n3iwfSNSocket(), err)
		return
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: encode: %v", err)
		return
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(35 * time.Second))
	var reply n3iwfSNAddReply
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&reply); err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: decode reply: %v", err)
		return
	}
	logger.NgapLog.Infof("N3IWF-SN: SN-Add reply status=%s DL-TEID=%d N3=%s UEIP=%s err=%q",
		reply.Status, reply.DownlinkTEID, reply.N3IWFN3Addr, reply.UEInnerIP, reply.Error)

	// A4: on a live SN leg, inject the N3IWF DL tunnel as
	// AdditionalDLQosFlowPerTNLInformation into the gNB's base modify-indication
	// transfer (keeping the mandatory MN DLQosFlowPerTNLInformation intact) and
	// push a follow-up Update SM Context so the SMF installs the second DL FAR.
	if reply.Status != "ok" {
		return
	}
	var t ngapType.PDUSessionResourceModifyIndicationTransfer
	if err := aper.UnmarshalWithParams(baseTransfer, &t, "valueExt"); err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: A4 decode base transfer: %v", err)
		return
	}
	teid := make([]byte, 4)
	binary.BigEndian.PutUint32(teid, reply.DownlinkTEID)
	t.AdditionalDLQosFlowPerTNLInformation = &ngapType.QosFlowPerTNLInformationList{
		List: []ngapType.QosFlowPerTNLInformationItem{
			{
				QosFlowPerTNLInformation: ngapType.QosFlowPerTNLInformation{
					UPTransportLayerInformation: ngapType.UPTransportLayerInformation{
						Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
						GTPTunnel: &ngapType.GTPTunnel{
							TransportLayerAddress: ngapConvert.IPAddressToNgap(reply.N3IWFN3Addr, ""),
							GTPTEID:               ngapType.GTPTEID{Value: teid},
						},
					},
					AssociatedQosFlowList: ngapType.AssociatedQosFlowList{
						List: []ngapType.AssociatedQosFlowItem{
							{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}},
						},
					},
				},
			},
		},
	}
	buf, err := aper.MarshalWithParams(t, "valueExt")
	if err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: A4 marshal transfer: %v", err)
		return
	}
	if _, _, _, err := consumer.GetConsumer().SendUpdateSmContextN2Info(
		amfUe, smContext, models.N2SmInfoType_PDU_RES_MOD_IND, aper.OctetString(buf)); err != nil {
		logger.NgapLog.Errorf("N3IWF-SN: A4 follow-up UpdateSmContext failed: %v", err)
		return
	}
	logger.NgapLog.Infof("N3IWF-SN: A4 installed DC tunnel at SMF PDU=%d DL-TEID=%d N3=%s",
		pduSessionID, reply.DownlinkTEID, reply.N3IWFN3Addr)
}

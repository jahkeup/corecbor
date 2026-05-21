package edhoc

import "fmt"

type OSCOREContext struct {
	MasterSecret []byte
	MasterSalt   []byte
	SenderID     []byte
	RecipientID  []byte
}

// Export derives application keying material using the EDHOC Exporter.
func (i *Initiator) Export(label int, context []byte, length int) ([]byte, error) {
	if i.state != initiatorStateComplete {
		return nil, ErrStateViolation
	}
	return edhocExport(i.prk4e3m, i.th4, label, context, length)
}

// Export derives application keying material using the EDHOC Exporter.
func (r *Responder) Export(label int, context []byte, length int) ([]byte, error) {
	if r.state != responderStateComplete {
		return nil, ErrStateViolation
	}
	return edhocExport(r.prk4e3m, r.th4, label, context, length)
}

func edhocExport(prk, th4 []byte, label int, context []byte, length int) ([]byte, error) {
	exportLabel := fmt.Sprintf("EDHOC_Exporter_%d", label)
	info, err := encodeExporterInfo(th4, exportLabel, context, length)
	if err != nil {
		return nil, err
	}
	return hkdfExpand(prk, info, length)
}

func (i *Initiator) ExportOSCORE() (*OSCOREContext, error) {
	if i.state != initiatorStateComplete {
		return nil, ErrStateViolation
	}

	masterSecret, err := edhocKDF(i.prk4e3m, i.th4, "OSCORE_Master_Secret", 16)
	if err != nil {
		return nil, err
	}
	masterSalt, err := edhocKDF(i.prk4e3m, i.th4, "OSCORE_Master_Salt", 8)
	if err != nil {
		return nil, err
	}

	return &OSCOREContext{
		MasterSecret: masterSecret,
		MasterSalt:   masterSalt,
		SenderID:     i.connectionID,
		RecipientID:  i.peerConnID,
	}, nil
}

func (r *Responder) ExportOSCORE() (*OSCOREContext, error) {
	if r.state != responderStateComplete {
		return nil, ErrStateViolation
	}

	masterSecret, err := edhocKDF(r.prk4e3m, r.th4, "OSCORE_Master_Secret", 16)
	if err != nil {
		return nil, err
	}
	masterSalt, err := edhocKDF(r.prk4e3m, r.th4, "OSCORE_Master_Salt", 8)
	if err != nil {
		return nil, err
	}

	return &OSCOREContext{
		MasterSecret: masterSecret,
		MasterSalt:   masterSalt,
		SenderID:     r.connectionID,
		RecipientID:  r.peerConnID,
	}, nil
}

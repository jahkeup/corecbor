package edhoc

type OSCOREContext struct {
	MasterSecret []byte
	MasterSalt   []byte
	SenderID     []byte
	RecipientID  []byte
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

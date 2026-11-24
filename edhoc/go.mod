module github.com/jahkeup/corecbor/edhoc

go 1.26.0

require (
	github.com/jahkeup/corecbor v0.3.2
	github.com/jahkeup/corecbor/cose v0.3.2
	github.com/jahkeup/corecbor/cwt v0.3.2
	golang.org/x/crypto v0.51.0
)

require golang.org/x/sys v0.44.0 // indirect

replace (
	github.com/jahkeup/corecbor => ../
	github.com/jahkeup/corecbor/cose => ../cose
	github.com/jahkeup/corecbor/cwt => ../cwt
)

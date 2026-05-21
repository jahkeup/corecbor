module github.com/jahkeup/corecbor/eat

go 1.25.0

require (
	github.com/jahkeup/corecbor v0.0.0
	github.com/jahkeup/corecbor/cose v0.0.0
	github.com/jahkeup/corecbor/cwt v0.0.0
)

replace (
	github.com/jahkeup/corecbor => ../
	github.com/jahkeup/corecbor/cose => ../cose
	github.com/jahkeup/corecbor/cwt => ../cwt
)

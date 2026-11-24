module github.com/jahkeup/corecbor/eat

go 1.26.0

require (
	github.com/jahkeup/corecbor v0.3.2
	github.com/jahkeup/corecbor/cose v0.3.2
	github.com/jahkeup/corecbor/cwt v0.3.2
)

replace (
	github.com/jahkeup/corecbor => ../
	github.com/jahkeup/corecbor/cose => ../cose
	github.com/jahkeup/corecbor/cwt => ../cwt
)

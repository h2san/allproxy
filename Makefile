LOCAL := $(GOPATH)/bin/allproxy-client 
SERVER := $(GOPATH)/bin/allproxy-server 
CGO := CGO_ENABLED=1

all:$(LOCAL) $(SERVER)

.PHONY:clean

clean:
	rm -f $(LOCAL) $(SERVER)

$(LOCAL):*.go cmd/allproxy-client/*.go 
	cd cmd/allproxy-client; $(CGO) go install

$(SERVER):*.go  cmd/allproxy-server/*.go
	cd cmd/allproxy-server; $(CGO) go install

local:$(LOCAL)

server:$(SERVER)
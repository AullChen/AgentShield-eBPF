FROM alpine:3.22.5

RUN apk add --no-cache curl

COPY run-demo.sh /usr/local/bin/agentshield-run-demo
RUN chmod 0555 /usr/local/bin/agentshield-run-demo

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentshield-run-demo"]

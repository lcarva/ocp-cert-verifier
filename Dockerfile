FROM fedora

RUN dnf install -y \
    python3-openshift \
    python3-pyOpenSSL\
    python3-requests \
    && dnf clean all

WORKDIR /src
COPY . .
RUN pip3 install --no-deps .

USER 1001
CMD ["/usr/local/bin/ocp-cert-verify"]

FROM ubuntu:26.04@sha256:fed6ddb82c61194e1814e93b59cfcb6759e5aa33c4e41bb3782313c2386ed6df AS ubuntu_qemu
RUN apt-get update -y
RUN apt-get install qemu-system-x86 -y

FROM pwn.red/jail as jail

COPY --from=ubuntu_qemu / /srv

RUN mkdir -p /srv/app
COPY image.bin /srv/app/image.bin
RUN chmod 444 /srv/app/image.bin
COPY start.sh /srv/app/run
RUN chmod 555 /srv/app/run

# For QEMU temporary disk files
RUN mkdir -p /srv/var/tmp/

FROM scratch
COPY --from=jail / /
COPY setup_jail_with_kvm.sh /bin/setup_jail_with_kvm.sh
RUN chmod 555 /bin/setup_jail_with_kvm.sh

CMD ["/bin/setup_jail_with_kvm.sh"]

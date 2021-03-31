FROM debian:jessie AS build

# Step 1: build tentacool
WORKDIR /tmp
RUN apt-get update && apt-get install -y \
	build-essential \
	dh-autoreconf \
	git \
	libcppunit-dev \
	libpoco-dev
RUN git clone https://github.com/tentacool/tentacool.git
RUN cd tentacool && autoreconf -i && ./configure && make

# Step 2: make final image
FROM debian:jessie-slim

WORKDIR /usr/app
RUN apt-get update && apt-get install -y libpoco-dev && mkdir data
COPY --from=build /tmp/tentacool/tentacool /usr/local/bin/tentacool
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod a+x /usr/local/bin/entrypoint.sh

EXPOSE 10000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

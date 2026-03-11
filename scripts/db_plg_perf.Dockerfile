FROM ubuntu:24.04

#Install utils
RUN apt update && apt install -y curl gpg lsb-release coreutils git unzip build-essential cmake libcmocka-dev libpcre2-dev

#Install Redis DB
RUN curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
RUN chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb jammy main" | tee /etc/apt/sources.list.d/redis.list
RUN apt update && apt install -y redis-stack-server

#Install Mongo DB
RUN curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor
RUN echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-8.0.list
RUN apt update && apt install -y mongodb-org
RUN mkdir /mongo_dump

#Fetch hiredis
RUN git clone https://github.com/redis/hiredis.git

#Fetch libmongoc
RUN git clone https://github.com/mongodb/mongo-c-driver.git
RUN mv mongo-c-driver /libmongoc

#Fetch libyang
RUN curl -fOL https://github.com/CESNET/libyang/archive/refs/heads/devel.zip && unzip devel.zip && mv libyang-devel /libyang

#Fetch sysrepo
RUN curl -fOL https://github.com/sysrepo/sysrepo/archive/refs/heads/devel.zip && unzip devel.zip && mv sysrepo-devel /sysrepo

#Install hiredis
WORKDIR /hiredis
RUN make -j8 && make install

#Install libmongoc
WORKDIR /libmongoc
RUN cmake -S . -B ./_build -DENABLE_EXTRA_ALIGNMENT=OFF -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_MONGOC=ON -DCMAKE_POLICY_VERSION_MINIMUM=3.5
RUN cmake --build ./_build --config RelWithDebInfo --parallel
RUN cmake --install "./_build" --prefix "/usr/local"

#Install libyang
RUN mkdir /libyang/build
WORKDIR /libyang/build
RUN cmake -DCMAKE_BUILD_TYPE=Release ..
RUN make -j8 && make install

#Build sysrepo
RUN mkdir /sysrepo/build
WORKDIR /sysrepo/build
RUN cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_DS_REDIS=ON -DENABLE_DS_MONGO=ON -DENABLE_PERF_TESTS=ON ..
RUN make -j8

#Create db start script
RUN echo '#!/bin/bash' > /back.sh
RUN echo '' >> /back.sh
RUN echo 'redis-stack-server > /dev/null &' >> /back.sh
RUN echo 'mongod --dbpath /mongo_dump > /dev/null &' >> /back.sh
RUN chmod +x /back.sh

#Create start script
RUN echo '#!/bin/bash' > /start.sh
RUN echo '' >> /start.sh
RUN echo '/sysrepo/build/tests/sr_perf 1000 10' >> /start.sh
RUN echo '/sysrepo/build/tests/sr_perf 10000 10' >> /start.sh
RUN echo '/sysrepo/build/tests/sr_perf 100000 10' >> /start.sh
RUN chmod +x /start.sh

CMD ["/bin/bash", "-c", "/back.sh;/start.sh"]

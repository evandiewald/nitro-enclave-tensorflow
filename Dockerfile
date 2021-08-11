
FROM python:3.7.11-slim-buster
# check on our entropy at initialization
RUN cat /proc/sys/kernel/random/entropy_avail
RUN apt-get update -y && apt-get install -y git curl gnupg build-essential libssl-dev libffi-dev python3-dev rng-tools openssh-client openssl haveged

# start the rngd daemon
RUN rngd -r /dev/urandom -o /dev/random
RUN sleep 20
RUN cat /proc/sys/kernel/random/entropy_avail

# copy files and model
COPY vsock-enclave-bidirectional.py .
COPY crypto_utils.py .
COPY requirements.txt .
COPY predict_tflite.py .
COPY skin_lesion_model.tflite .

RUN pip3 install --upgrade pip
RUN python3 -m pip install --upgrade setuptools
RUN pip3 install numpy==1.16.0

# pre-built tensorflow lite runtime wheel
RUN pip3 install https://github.com/iCorv/tflite-runtime/raw/master/tflite_runtime-2.4.0-cp37-cp37m-linux_x86_64.whl
RUN pip3 install -r requirements.txt

# generate our enclave's rsa keypair
RUN ssh-keygen -t rsa -f my_key -m PEM -N "" && ssh-keygen -f my_key.pub -m 'PEM' -e > my_public_key.pem && openssl rsa -in my_key -outform pem > my_private_key.pem

# launch the python script
CMD ["/usr/local/bin/python3", "-u", "vsock-enclave-bidirectional.py", "3", "5005", "5006"]
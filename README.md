# nitro-enclave-tensorflow

Code for running a confidential, tensorflow-based classification of skin cancer images within an AWS Nitro Enclave. The user's data can only be decrypted within the secure enclave, and the inference can only be decrypted by the user. 

## Scenario
1. Parent instance (rich application) starts a vsock server that listens for data from the enclave.
2. Enclave is initialized with its own RSA keypair, which is not visible to the host instance and is erased when the enclave is closed.
3. Enclave sends its public key to the parent server and begins listening for a response.
4. Parent receives key, encrypts image using the enclave's pub key (acting as or on behalf of the user for simplicity). 
5. Parent sends its public key, the encrypted image, and the encrypted symmetric key to the enclave. 
6. Enclave receives these files, decrypts the image, invokes the tensorflow lite model, encrypts the classification result, and sends it back the parent server. 
7. Parent receives the encrypted classification result, decrypts it (again, this is a proxy for sending the file to the actual patient), and prints it out. 

## Setup
- Login to your instance via SSH and update with

`sudo yum update`

- Install docker and the Nitro CLI.

`sudo amazon-linux-extras install docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y`

- Start the docker service.

`sudo service docker start`

- Elevate user privileges for docker and nice editor.

`sudo usermod -aG ne ec2-user && sudo usermod -aG docker ec2-user `

- Next, we need to configure the resources (CPU cores and memory) that our enclave will be able to access. Edit the `/etc/nitro_enclaves/allocator.yaml` file and increase the default values to 8192 MB RAM and 4 cores (though I'm sure you can get away with less). To submit these changes, run 

`sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service `

- At this point, reboot your instance to allow the various updates to take effect. 

- After the reboot, clone the public repository

`git clone https://github.com/evandiewald/nitro-enclave-tensorflow.git `

- And cd into the repo directory. Build the docker image with

`docker build -t enclave-tensorflow . `

- Once the image is created successfully, we use the Nitro CLI to convert it into an EIF file:

`nitro-cli build-enclave --docker-uri enclave-tensorflow:latest --output-file enclave-tensorflow.eif `

- If all goes well, you'll see an attestation document with 3 SHA hashes, which correspond to the enclave image, kernel, and application.

- Before we run the enclave, we need to make sure our parent instance is listening for a connection. Open up a new terminal and run 

`python3 vsock-parent.py server 5006` The console should print `Server ready! `

- Back in the first terminal, let's finally execute our enclave application. Again, we'll use the Nitro CLI

`nitro-cli run-enclave --eif-path enclave-tensorflow.eif --memory 8192 --cpu-count 4 --enclave-cid 16 --debug-mode `

- A successful output will show some basic metadata about the enclave and its resources.

- Take note of the EnclaveID, which you will need in the next step. As soon as the enclave boots, the server in the other terminal should print out Enclave's public key received. But it would be nice to know what was going on in our enclave for debugging purposes. Since we included the `--debug-mode` flag, the Nitro CLI exposes a console that will allow us to view the output from our application and make sure it's running properly. 

`nitro-cli console --enclave-id $ENCLAVE_ID `

- You'll be greeted with a long list of printouts describing the boot operations, but at the bottom you should see some messages from our python application.
At this point, open up a third terminal and send the keys from parent to enclave with

`python3 vsock-parent.py client 16 5005` (16 is the Enclave CID)

- This terminal should indicate that it is sending the parent's public key, encrypted image, and symmetric key. 
Back in the enclave console, the application will acknowledge that it received and decrypted the messages before classifying the image, encrypting the inference, and sending it back to the parent server. At this point the enclave will shut down, giving a connection error. 

- Finally, the server will receive the inference, decrypt it, and print out the results!

- :exclamation: Don't forget to terminate your EC2 instance to prevent further charges.

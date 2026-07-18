# CoAP-EAP 

This repository contains a C implementation of CoAP-EAP ([RFC 9820](https://datatracker.ietf.org/doc/rfc9820/)), based on [uOSCORE-uEDHOC 3.0.5](https://github.com/eriptic/uoscore-uedhoc) library, which uses [EAP-PSK](https://datatracker.ietf.org/doc/html/rfc4764) and [EAP-EDHOC](https://datatracker.ietf.org/doc/draft-ietf-emu-eap-edhoc/) as EAP methods. There are up to three EDHOC authentication methods available for testing EAP-EDHOC: EDHOC methods 0, 3 and 4 ([EDHOC-PSK](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc-psk/)). A Dockerized scenario is included for testing purposes on a laptop running Ubuntu 22.04 OS.

## Requirements
* A laptop with Ubuntu 22.04 operating system.
* Docker.

## IP addresses
* EAP Peer (CoAP Server): `127.0.0.1`.
* EAP Authenticator (CoAP Client): `127.0.0.2`.
* FreeRADIUS or EAP Server: `127.0.0.3`.

## How to build and run
* After cloning the repository, navigate to it and execute `up.sh`. This builds the Docker image containing the solution and runs a Docker container which uses the previously built Docker image.

* Execute `docker exec -it c-coap-eap-h1-1 /bin/bash` to get an interactive terminal in the container (we will refer to this as the EAP Authenticator terminal).
* Once into the container, browse until `/home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/initiator_client/`. Execute `make` to build the EAP Authenticator.

* Execute `docker exec -it c-coap-eap-h1-1 /bin/bash` to get another terminal in the container (we will refer to this as the EAP Peer terminal).
* Browse until `/home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/responder_server/` and execute `make` to build the EAP Peer.

* Execute `docker exec -it c-coap-eap-h1-1 /bin/bash` to get a new terminal in the container (we will refer to this as the EAP Server terminal).
* Browse until `/home/uedhoc/freeradius-server-3.2.3/` and execute the following commands to build the EAP Server:
    - `./configure`.
    - `make`.
    - `make install`.

* If desired, execute again `docker exec -it c-coap-eap-h1-1 /bin/bash` followed by `tcpdump -i any -w proof_coap_eap.pcap` to capture the traffic in another terminal.

* In order to run CoAP-EAP (by default, CoAP-EAP runs five times; this can be changed in the `main` function of the EAP Peer and the EAP Authenticator codes):

    - In the EAP Authenticator terminal, execute `./build/initiator_client` to run the EAP Authenticator (it will be waiting for the initial message from the EAP Peer).
    - In the EAP Server terminal, execute `./radius.sh` to start the EAP Server.
    - Back to the EAP Peer terminal, execute `./build/responder_server` to run the EAP Peer.

* How to clean the compilation:
  - Execute `make clean` in `initiator_client` and `responder_server` folders from the EAP Authenticator and EAP Peer terminals, respectively.
  - Execute `make uninstall`, `rm -rf /usr/local/etc/raddb`, `make clean`, `make distclean` in `freeradius-server-3.2.3` folder from the EAP Server terminal.
  - Exit the container's terminals and execute `./down.sh` to stop and remove the Docker container.

## How to change the EAP method from EAP-EDHOC to EAP-PSK
* Go to `home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/responder_server/src/main.cpp` and `home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/initiator_client/src/main.cpp` and, change line ```EAP__METHOD method = EAP__EDHOC;``` to ```EAP__METHOD method = EAP__PSK;```.
* Go to `home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/peer_state_machine/eap-peer.c` and take a look at this block of code:

```
	if (eapRestart)
	{	
		selectedMethod = NONE;
		methodState = NONE;
		decision = FAIL;
		lastId = NONE;
		eapSuccess = FALSE;
		eapFail = FALSE;
		eapKeyAvailable = FALSE;

		// Initialization out of standard
		eapReq = FALSE;
		eapResp = FALSE;
		eapNoResp = FALSE;
		memset(eapRespData, 0, EAP_MSG_LEN);

		if (edhoc_data != NULL)
			edhoc_data = NULL;

		edhoc_data = initMethodEap_edhoc();

		eapRestart = FALSE;
		return;
	}
```
  Change it to the following code:

```
	if (eapRestart)
	{	
		selectedMethod = NONE;
		methodState = NONE;
		decision = FAIL;
		lastId = NONE;
		eapSuccess = FALSE;
		eapFail = FALSE;
		eapKeyAvailable = FALSE;

		// Initialization out of standard
		eapReq = FALSE;
		eapResp = FALSE;
		eapNoResp = FALSE;
		memset(eapRespData, 0, EAP_MSG_LEN);

		initMethodEap_psk();

		eapRestart = FALSE;
		return;
	}
```

* Go to `home/uedhoc/freeradius-server-3.2.3/raddb/mods-available/eap` and change line ```default_eap_type = EDHOC``` to ```default_eap_type = psk```.

* Clean the compilation for all EAP entities, recompile and run again.

## How to change the EDHOC authentication method used in EAP-EDHOC

* By default, method 0 is used. If another method is to be used, go to `eap-edhoc.c` file in `/home/uedhoc/uoscore-uedhoc-3.0.5-coap-eap/samples/linux_coap_eap/peer_state_machine/` and change the value of ```uint8_t TEST_VEC_NUM = 1;```:
  - If method 3 is desired, the value should be 5.
  - If method 4 is desired, the value should be 7.
* Go to `home/uedhoc/freeradius-server-3.2.3/src/modules/rlm_eap/types/rlm_eap_edhoc/eap_edhoc.h` and change ```#define TEST_VECTORS_NUM 1``` to the value used in the previous step.
  - For example, if method 4 is desired, it should be ```#define TEST_VECTORS_NUM 7```.

## For further information
* If you still have any questions after following the steps, please do not hesitate to contact the repository author by email: i.alvarezbelotto@um.es.
* In addition, the code that simulates packet loss due to congestion on the channel used for communication between the EAP Authenticator and the EAP Peer, along with raw measurement data, firmware configuration files and plotting scripts, can be provided upon request.

## Acknowledgments

- IETF.
- University of Murcia.
- University of Oviedo.
- Open Source Projects: Docker, uOSCORE-uEDHOC.

## Authors

- Iván Álvarez-Belotto (University of Murcia).

- Francisco López-Gómez (University of Murcia).

- Dan García-Carrillo (University of Oviedo).

- Gabriel López-Millán (University of Murcia).

- Rafael Marín-López (University of Murcia).

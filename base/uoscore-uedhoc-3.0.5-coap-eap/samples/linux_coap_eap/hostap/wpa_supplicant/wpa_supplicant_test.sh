#!/bin/bash

rm -rf /var/run/wpa_supplicant/wlo1

./wpa_supplicant -i wlo1 -c wpa_supplicant_test.conf

#!/bin/bash

cmake --build build --target nchat
sleep 2
./build/bin/nchat


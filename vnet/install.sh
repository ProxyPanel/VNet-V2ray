#!/usr/bin/env bash

# vnet-v2ray install script

NODE_ID=""
NODE_KEY=""
HOST=""
ACTION="install"

while [[ $# -gt 0 ]]; do
  key=$1
  case $key in
  --node_id)
    NODE_ID="$2"
    shift
    ;;
  --node_key)
    NODE_KEY="$2"
    shift
    ;;
  --host)
    HOST="$2"
    shift
    ;;
  --action)
    ACTION="$2"
    shift
    ;;
  *) ;;
  esac
done


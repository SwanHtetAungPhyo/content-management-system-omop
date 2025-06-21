#!/usr/bin/env bash

FRONTEND="frontend"
BACKEND="backend"

mkdir -p "${FRONTEND}"
mkdir -p "${BACKEND}/apigateway" "${BACKEND}/services"

mkdir  -p ".github/workflows"